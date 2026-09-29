<#
.SYNOPSIS
    Provision the Arbiterion analysis VM: Sysmon, Python + collector deps, LuaJIT, and the
    endpoint collector pointed at the host's Arbiterion API.

.DESCRIPTION
    Runs INSIDE the Windows guest (via VBoxManage guestcontrol). Reads everything it needs
    from a temporary shared folder mounted at $StagingDrive. After provisioning the host
    script removes that share, so no staging material remains on disk afterwards.

    Steps:
      1. Mount the staging share (net use \\vboxsrv\<share>).
      2. Install Sysmon with the SwiftOnSecurity config (already includes Event 13 registry rules).
      3. Install Python silently from a staged installer.
      4. pip install httpx + python-dotenv OFFLINE from staged wheels.
      5. Install LuaJIT from a staged archive and verify require("ffi").
      6. Install the Arbiterion collector and register an ONLOGON scheduled task.
      7. Send a synthetic "Defender tampering" event to verify end-to-end connectivity.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Endpoint,

    [Parameter(Mandatory = $true)]
    [string]$LoginUrl,

    [Parameter(Mandatory = $true)]
    [string]$Secret,

    [Parameter(Mandatory = $true)]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [string]$Password,

    [Parameter(Mandatory = $true)]
    [string]$StagingShare,

    [string]$StagingDrive = "Z:",

    [string]$HostId = ""
)

$ErrorActionPreference = "Stop"

function Write-Step($Message) {
    Write-Host "`n[PROVISION] $Message" -ForegroundColor Cyan
}

function Test-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw "provision-vm.ps1 must run as Administrator (the 'analyst' account is a local admin)."
}

if ([string]::IsNullOrWhiteSpace($HostId)) {
    $HostId = $env:COMPUTERNAME
}

$DestRoot = "C:\ProgramData\Arbiterion"
$SysmonDir = Join-Path $DestRoot "sysmon"
$PyRoot    = Join-Path $DestRoot "python"
$LuaJitDir = Join-Path $DestRoot "luajit"
$ColDir    = Join-Path $DestRoot "collector"

# ---------------------------------------------------------------- staging share
Write-Step "Mounting staging share \\vboxsrv\$StagingShare as $StagingDrive"
if (-not (Test-Path "$StagingDrive\")) {
    net use "$StagingDrive" "\\vboxsrv\$StagingShare" /persistent:no | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to mount \\vboxsrv\$StagingShare. Is Guest Additions installed and the share attached?"
    }
}
$Staging = "$StagingDrive\"

# ---------------------------------------------------------------- directories
New-Item -ItemType Directory -Force -Path $SysmonDir | Out-Null
New-Item -ItemType Directory -Force -Path $PyRoot    | Out-Null
New-Item -ItemType Directory -Force -Path $LuaJitDir | Out-Null
New-Item -ItemType Directory -Force -Path $ColDir    | Out-Null

# ---------------------------------------------------------------- Sysmon
Write-Step "Installing Sysmon"
$sysmonBin  = Join-Path $Staging "sysmon\Sysmon64.exe"
$sysmonConf = Join-Path $Staging "sysmon\sysmonconfig-export.xml"
if (-not (Test-Path $sysmonBin)) { throw "Missing $sysmonBin in staging share." }
if (-not (Test-Path $sysmonConf)) { throw "Missing $sysmonConf in staging share." }

Copy-Item $sysmonBin  $SysmonDir -Force
Copy-Item $sysmonConf $SysmonDir -Force
$installedSysmon = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
if (-not $installedSysmon) {
    $proc = Start-Process -FilePath (Join-Path $SysmonDir "Sysmon64.exe") -ArgumentList "-accepteula -i `"$(Join-Path $SysmonDir 'sysmonconfig-export.xml')`"" -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) { throw "Sysmon install failed with exit code $($proc.ExitCode)." }
} else {
    Write-Host "Sysmon service already installed."
}

# ---------------------------------------------------------------- Python
Write-Step "Installing Python"
$pyInstaller = Join-Path $Staging "python\python-installer.exe"
if (-not (Test-Path $pyInstaller)) { throw "Missing $pyInstaller in staging share." }

$pythonExe = Join-Path $PyRoot "python.exe"
if (-not (Test-Path $pythonExe)) {
    $args = "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_pip=1 Include_launcher=1"
    $proc = Start-Process -FilePath $pyInstaller -ArgumentList $args -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) { throw "Python install failed with exit code $($proc.ExitCode)." }
    if (-not (Test-Path $pythonExe)) {
        $pythonExe = Join-Path $env:ProgramFiles "Python311\python.exe"
    }
    if (-not (Test-Path $pythonExe)) {
        $found = Get-ChildItem $env:ProgramFiles -Directory -Filter "Python*" -ErrorAction SilentlyContinue |
                 Select-Object -First 1
        if ($found) { $pythonExe = Join-Path $found.FullName "python.exe" }
    }
    if (-not (Test-Path $pythonExe)) { throw "Python install completed but python.exe not found." }
} else {
    Write-Host "Python already installed at $pythonExe"
}

# Refresh PATH from registry so pip/python resolve in this session
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User") + ";" + $env:Path

# ---------------------------------------------------------------- pip deps (offline)
Write-Step "Installing collector dependencies (offline wheels)"
$wheelsDir = Join-Path $Staging "wheels"
if (-not (Test-Path $wheelsDir)) { throw "Missing $wheelsDir in staging share." }
& $pythonExe -m pip install --no-index --find-links $wheelsDir httpx python-dotenv
if ($LASTEXITCODE -ne 0) { throw "pip install failed (exit $LASTEXITCODE)." }

# ---------------------------------------------------------------- LuaJIT
Write-Step "Installing LuaJIT"
$ljInstaller = Get-ChildItem (Join-Path $Staging "luajit") -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $ljInstaller) { throw "No LuaJIT installer found in staging\luajit." }
Write-Host "Installing $($ljInstaller.Name) silently..."
$proc = Start-Process -FilePath $ljInstaller.FullName -ArgumentList "/S" -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "LuaJIT installer failed with exit code $($proc.ExitCode)." }

$ljExe = Get-ChildItem $env:ProgramFiles -Filter "luajit.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue |
         Where-Object { $_.FullName -match "LuaJIT|luajit" } | Select-Object -First 1
if (-not $ljExe) {
    $ljExe = Get-ChildItem (Join-Path $env:LOCALAPPDATA "Programs") -Filter "luajit.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $ljExe) {
    $ljExe = Get-ChildItem "C:\Program Files\LuaJIT*" -Filter "luajit.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $ljExe) { throw "luajit.exe not found after install. Expected under Program Files\LuaJIT*." }
Write-Host "LuaJIT at $($ljExe.FullName)"
Copy-Item $ljExe.FullName $LuaJitDir -Force -ErrorAction SilentlyContinue

$ffiCheck = & $ljExe.FullName -e "print(require('ffi') and 'ffi-ok' or 'ffi-missing')" 2>&1
if ($LASTEXITCODE -ne 0 -or "$ffiCheck" -notmatch "ffi-ok") {
    throw "LuaJIT ffi check failed: $ffiCheck"
}
Write-Host "ffi check: $ffiCheck"

# ---------------------------------------------------------------- static IP (host-only)
Write-Step "Configuring static host-only IP 192.168.56.101"
$nic = (Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1).Name
if ($nic) {
    netsh interface ipv4 set address name="$nic" static 192.168.56.101 255.255.255.0 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "netsh static IP failed; the collector only needs outbound access to 192.168.56.1."
    } else {
        Write-Host "Set $nic to 192.168.56.101/24"
    }
} else {
    Write-Warning "No active physical adapter found; skipping static IP (host-only link still allows 192.168.56.1)."
}

# ---------------------------------------------------------------- collector
Write-Step "Installing Arbiterion collector"
Copy-Item (Join-Path $Staging "collector.py") $ColDir -Force
if (Test-Path (Join-Path $Staging "requirements.txt")) {
    Copy-Item (Join-Path $Staging "requirements.txt") $ColDir -Force
}

$env:COLLECTOR_ENDPOINT = $Endpoint
$env:COLLECTOR_LOGIN_URL = $LoginUrl
$env:COLLECTOR_USERNAME  = $Username
$env:COLLECTOR_PASSWORD  = $Password
$env:COLLECTOR_SHARED_SECRET = $Secret
$env:COLLECTOR_HOST_ID   = $HostId

# Persistent launcher (pythonw => no console window on logon)
$cmdPath = Join-Path $ColDir "run-collector.cmd"
@"
@echo off
set COLLECTOR_ENDPOINT=$Endpoint
set COLLECTOR_LOGIN_URL=$LoginUrl
set COLLECTOR_USERNAME=$Username
set COLLECTOR_PASSWORD=$Password
set COLLECTOR_SHARED_SECRET=$Secret
set COLLECTOR_HOST_ID=$HostId
"$pythonExe" "$ColDir\collector.py" --interval 20 --lookback 120
"@ | Set-Content -Path $cmdPath -Encoding ASCII

# Start it now (detonation phase runs shortly after provisioning)
Start-Process -FilePath $cmdPath -WindowStyle Hidden
Write-Host "Collector started in background."

# ONLOGON scheduled task so it survives a reboot before detonation
$taskAction = "cmd.exe /c `"$cmdPath`" >nul 2>&1"
schtasks /Create /TN "ArbiterionCollector" /TR $taskAction /SC ONLOGON /RL LIMITED /F | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Warning "Failed to register ONLOGON task (exit $LASTEXITCODE); collector runs in-process only." }

# ---------------------------------------------------------------- smoke test
Write-Step "Forwarding synthetic Defender-tampering event (end-to-end check)"
$smokePy = Join-Path $ColDir "forward-test.py"
@"
import argparse
import hashlib
import hmac
import json
import sys

import httpx


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", required=True)
    p.add_argument("--login-url", required=True)
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--secret", required=True)
    p.add_argument("--host-id", required=True)
    args = p.parse_args()

    payload = {
        "host_id": args.host_id,
        "event_type": "process_create",
        "summary": (
            f"Synthetic Defender-tampering attempt on {args.host_id}: "
            "Add-MpPreference exclusion for SystemDrive."
        ),
        "severity_hint": "High",
        "username": "analyst",
        "source_ip": None,
        "process_name": "powershell.exe",
        "command_line": (
            'powershell "Start-Process powershell -Verb runAs" -WindowStyle hidden '
            "-Argument 'Add-MpPreference -ExclusionPath $env:SystemDrive -ExclusionExtension .exe, .dll -Force'"
        ),
        "indicators": ["powershell.exe", "Add-MpPreference", "SystemDrive"],
        "telemetry": [
            "Log: Microsoft-Windows-Sysmon/Operational",
            "Event ID: 1",
            "Provider: Microsoft-Windows-Sysmon",
            "Parent command line: C:\\Windows\\System32\\cmd.exe",
        ],
        "metadata": {"synthetic": True, "purpose": "provision-smoke-test"},
    }

    raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = "sha256=" + hmac.new(args.secret.encode(), raw_body, hashlib.sha256).hexdigest()

    with httpx.Client(timeout=20.0) as client:
        login = client.post(args.login_url, json={"email": args.username, "password": args.password})
        login.raise_for_status()
        resp = client.post(
            args.endpoint,
            content=raw_body,
            headers={"Content-Type": "application/json", "X-Signature": sig},
        )
        resp.raise_for_status()
        body = resp.json()
        print(f"SMOKE-OK alert_id={body.get('id')} pipeline_state={body.get('pipeline_state')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
"@ | Set-Content -Path $smokePy -Encoding UTF8

$result = & $pythonExe $smokePy --endpoint $Endpoint --login-url $LoginUrl --username $Username --password $Password --secret $Secret --host-id $HostId 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Smoke test failed: $result"
}
Write-Host $result -ForegroundColor Green

# ---------------------------------------------------------------- done
Write-Step "Provisioning complete"
Write-Host "  Host ID (collector): $HostId"
Write-Host "  LuaJIT:              $($ljExe.FullName)"
Write-Host "  Collector dir:       $ColDir"
Write-Host "  Staging share still mounted; remove it from the host when ready."
