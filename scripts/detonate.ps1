<#
.SYNOPSIS
    Guest-side detonation dispatcher for the Arbiterion analysis VM.

.DESCRIPTION
    Runs INSIDE the isolated Windows guest. Given a sample path, it picks the
    correct launcher for the file type and starts it, then writes a JSON result
    describing what it launched (runner, command line, pid, start time) to
    -ResultPath. The host orchestrator copies that result back into the report.

    It deliberately does NOT wait for the sample to finish or judge its
    behaviour: observation, telemetry and teardown are the host's job. It only
    guarantees the sample was launched the way a user/attacker would launch it,
    so the Sysmon/collector pipeline sees realistic process ancestry.

    Supported types (by extension):
      .exe .scr .com   -> executed directly
      .dll             -> rundll32 <dll>,<Export|#Ordinal>  (default: entry #1)
      .ps1             -> powershell -ExecutionPolicy Bypass -File
      .bat .cmd        -> cmd /c
      .js .jse .vbs .vbe .wsf -> wscript (GUI) or cscript (-Console)
      .hta             -> mshta
      .lnk .url        -> explorer (shell resolves the target)
      .doc* .xls* .ppt* -> start via shell (Office opens with macros per policy)
      .lua             -> luajit (back-compat with the original loader samples)
      *                -> start via shell association

    SECURITY: this script launches whatever it is pointed at. It must only ever
    be used inside the throwaway, host-only analysis VM, against a snapshot you
    intend to roll back. Never run it on a host you care about.

.PARAMETER SamplePath
    Full path to the sample inside the guest (e.g. C:\Users\analyst\Desktop\x.exe).

.PARAMETER DllExport
    For .dll samples, the export name or #ordinal rundll32 should call. Default '#1'.

.PARAMETER Arguments
    Optional extra arguments passed through to the sample / runner.

.PARAMETER ResultPath
    Where to write the JSON launch result. Default: <sample dir>\detonation-result.json.

.PARAMETER Console
    For script hosts, use cscript instead of wscript (visible console output).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File detonate.ps1 -SamplePath C:\Users\analyst\Desktop\loader.exe
    powershell -ExecutionPolicy Bypass -File detonate.ps1 -SamplePath C:\s\evil.dll -DllExport DllRegisterServer
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SamplePath,

    [string]$DllExport = "#1",

    [string]$Arguments = "",

    [string]$ResultPath = "",

    [switch]$Console,

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Resolve-LuaJit {
    # Returns the luajit path, or $null if not installed (callers that actually
    # launch a .lua sample must treat $null as an error; -DryRun tolerates it).
    $candidates = @(
        "C:\ProgramData\Arbiterion\luajit\luajit.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    $found = Get-ChildItem "C:\Program Files\LuaJIT*" -Filter luajit.exe -Recurse -ErrorAction SilentlyContinue |
             Select-Object -First 1 -ExpandProperty FullName
    if ($found) { return $found }
    return $null
}

# Decide runner + argument list purely from the extension. Returns a hashtable
# describing how to launch, so the logic is testable in isolation.
function Get-Launcher {
    param([string]$Path, [string]$Export, [string]$ExtraArgs, [bool]$UseConsole)

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $sysnative = "$env:WINDIR\System32"

    switch ($ext) {
        { $_ -in ".exe", ".scr", ".com" } {
            return @{ Type = "pe";     Exe = $Path; Args = $ExtraArgs }
        }
        ".dll" {
            $a = "`"$Path`",$Export"
            if ($ExtraArgs) { $a += " $ExtraArgs" }
            return @{ Type = "dll";    Exe = "$sysnative\rundll32.exe"; Args = $a }
        }
        ".ps1" {
            return @{ Type = "ps1";    Exe = "$sysnative\WindowsPowerShell\v1.0\powershell.exe";
                      Args = "-NoProfile -ExecutionPolicy Bypass -File `"$Path`" $ExtraArgs" }
        }
        { $_ -in ".bat", ".cmd" } {
            return @{ Type = "cmd";    Exe = "$sysnative\cmd.exe"; Args = "/c `"$Path`" $ExtraArgs" }
        }
        { $_ -in ".js", ".jse", ".vbs", ".vbe", ".wsf" } {
            $host_exe = if ($UseConsole) { "cscript.exe" } else { "wscript.exe" }
            return @{ Type = "script"; Exe = "$sysnative\$host_exe"; Args = "`"$Path`" $ExtraArgs" }
        }
        ".hta" {
            return @{ Type = "hta";    Exe = "$sysnative\mshta.exe"; Args = "`"$Path`" $ExtraArgs" }
        }
        { $_ -in ".lnk", ".url" } {
            return @{ Type = "shortcut"; Exe = "$sysnative\explorer.exe"; Args = "`"$Path`"" }
        }
        { $_ -in ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".rtf" } {
            return @{ Type = "office"; Exe = "$sysnative\cmd.exe"; Args = "/c start `"`" `"$Path`"" }
        }
        ".lua" {
            return @{ Type = "lua";    Exe = (Resolve-LuaJit); Args = "`"$Path`" $ExtraArgs" }
        }
        default {
            return @{ Type = "shell";  Exe = "$sysnative\cmd.exe"; Args = "/c start `"`" `"$Path`"" }
        }
    }
}

if (-not $DryRun -and -not (Test-Path $SamplePath)) { throw "Sample not found in guest: $SamplePath" }
if (-not $ResultPath) {
    $ResultPath = Join-Path (Split-Path -Parent $SamplePath) "detonation-result.json"
}

$launcher = Get-Launcher -Path $SamplePath -Export $DllExport -ExtraArgs $Arguments -UseConsole:$Console.IsPresent
Write-Host "[detonate] type=$($launcher.Type) exe=$($launcher.Exe)"
Write-Host "[detonate] args=$($launcher.Args)"

$startTime = (Get-Date).ToUniversalTime().ToString("o")
$pid_launched = $null
$errorText = $null

if ($DryRun) {
    $result = [ordered]@{
        schema       = "arbiterion.detonation-result/v1"
        dry_run      = $true
        sample       = $SamplePath
        sample_name  = (Split-Path $SamplePath -Leaf)
        extension    = [System.IO.Path]::GetExtension($SamplePath).ToLowerInvariant()
        runner_type  = $launcher.Type
        runner_exe   = $launcher.Exe
        runner_args  = $launcher.Args
        launched_pid = $null
        started_utc  = $startTime
    }
    $json = $result | ConvertTo-Json -Depth 4
    Write-Host $json
    if ($ResultPath) { $json | Set-Content -Path $ResultPath -Encoding UTF8 }
    exit 0
}

if ($launcher.Type -eq "lua" -and -not $launcher.Exe) {
    throw "luajit.exe not found in the guest; cannot detonate a .lua sample."
}

try {
    $argList = $launcher.Args
    if ([string]::IsNullOrWhiteSpace($argList)) {
        $proc = Start-Process -FilePath $launcher.Exe -PassThru -WindowStyle Normal
    } else {
        $proc = Start-Process -FilePath $launcher.Exe -ArgumentList $argList -PassThru -WindowStyle Normal
    }
    $pid_launched = $proc.Id
    Write-Host "[detonate] launched pid=$pid_launched"
} catch {
    $errorText = $_.Exception.Message
    Write-Warning "[detonate] launch failed: $errorText"
}

$result = [ordered]@{
    schema       = "arbiterion.detonation-result/v1"
    sample       = $SamplePath
    sample_name  = (Split-Path $SamplePath -Leaf)
    extension    = [System.IO.Path]::GetExtension($SamplePath).ToLowerInvariant()
    runner_type  = $launcher.Type
    runner_exe   = $launcher.Exe
    runner_args  = $launcher.Args
    launched_pid = $pid_launched
    started_utc  = $startTime
    hostname     = $env:COMPUTERNAME
    error        = $errorText
}
$result | ConvertTo-Json -Depth 4 | Set-Content -Path $ResultPath -Encoding UTF8
Write-Host "[detonate] result written to $ResultPath"

if ($errorText) { exit 1 }
exit 0
