<#
.SYNOPSIS
    Assertions for the detonate.ps1 type dispatcher. Runs anywhere pwsh exists
    (no Windows needed) by driving detonate.ps1 in -DryRun mode and checking the
    runner it would use for each sample extension.

.EXAMPLE
    pwsh -File tests/test_detonate_dispatch.ps1
    # exits 0 if all cases pass, 1 otherwise
#>
$ErrorActionPreference = "Stop"
$script = Join-Path $PSScriptRoot "..\scripts\detonate.ps1"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("detonate-test-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

# Each case: sample name -> expected runner_type and a substring expected in the exe.
$cases = @(
    @{ Name = "loader.exe";     Type = "pe";       ExeLike = "loader.exe" }
    @{ Name = "x.scr";          Type = "pe";       ExeLike = "x.scr" }
    @{ Name = "evil.dll";       Type = "dll";      ExeLike = "rundll32.exe" }
    @{ Name = "stage.ps1";      Type = "ps1";      ExeLike = "powershell.exe" }
    @{ Name = "run.bat";        Type = "cmd";      ExeLike = "cmd.exe" }
    @{ Name = "go.cmd";         Type = "cmd";      ExeLike = "cmd.exe" }
    @{ Name = "drop.js";        Type = "script";   ExeLike = "wscript.exe" }
    @{ Name = "macro.vbs";      Type = "script";   ExeLike = "wscript.exe" }
    @{ Name = "x.wsf";          Type = "script";   ExeLike = "wscript.exe" }
    @{ Name = "app.hta";        Type = "hta";      ExeLike = "mshta.exe" }
    @{ Name = "link.lnk";       Type = "shortcut"; ExeLike = "explorer.exe" }
    @{ Name = "invoice.docm";   Type = "office";   ExeLike = "cmd.exe" }
    @{ Name = "sheet.xlsm";     Type = "office";   ExeLike = "cmd.exe" }
    @{ Name = "beacon.lua";     Type = "lua";      ExeLike = $null }
    @{ Name = "payload.bin";    Type = "shell";    ExeLike = "cmd.exe" }
)

$failures = 0
foreach ($case in $cases) {
    $resultPath = Join-Path $tmp "result.json"
    $sample = "C:\Users\analyst\Desktop\$($case.Name)"
    & pwsh -NoProfile -File $script -SamplePath $sample -ResultPath $resultPath -DryRun *> $null
    if (-not (Test-Path $resultPath)) {
        Write-Host "FAIL $($case.Name): no result written" -ForegroundColor Red
        $failures++
        continue
    }
    $result = Get-Content $resultPath -Raw | ConvertFrom-Json
    $ok = $true
    if ($result.runner_type -ne $case.Type) {
        Write-Host "FAIL $($case.Name): runner_type=$($result.runner_type) expected=$($case.Type)" -ForegroundColor Red
        $ok = $false
    }
    if ($case.ExeLike -and ($result.runner_exe -notlike "*$($case.ExeLike)*")) {
        Write-Host "FAIL $($case.Name): runner_exe=$($result.runner_exe) expected like *$($case.ExeLike)*" -ForegroundColor Red
        $ok = $false
    }
    # The sample path must always be quoted into the args (except bare PE exec).
    if ($case.Type -notin @("pe") -and ($result.runner_args -notlike "*$($case.Name)*")) {
        Write-Host "FAIL $($case.Name): sample not referenced in args: $($result.runner_args)" -ForegroundColor Red
        $ok = $false
    }
    if ($ok) {
        Write-Host "PASS $($case.Name) -> $($result.runner_type)" -ForegroundColor Green
    } else {
        $failures++
    }
    Remove-Item $resultPath -Force -ErrorAction SilentlyContinue
}

# DLL export override is honoured.
$resultPath = Join-Path $tmp "dll.json"
& pwsh -NoProfile -File $script -SamplePath "C:\s\evil.dll" -DllExport "DllRegisterServer" -ResultPath $resultPath -DryRun *> $null
$dll = Get-Content $resultPath -Raw | ConvertFrom-Json
if ($dll.runner_args -notlike "*DllRegisterServer*") {
    Write-Host "FAIL dll export: $($dll.runner_args)" -ForegroundColor Red
    $failures++
} else {
    Write-Host "PASS dll export override" -ForegroundColor Green
}

# cscript when -Console is set.
$resultPath = Join-Path $tmp "console.json"
& pwsh -NoProfile -File $script -SamplePath "C:\s\x.js" -Console -ResultPath $resultPath -DryRun *> $null
$con = Get-Content $resultPath -Raw | ConvertFrom-Json
if ($con.runner_exe -notlike "*cscript.exe*") {
    Write-Host "FAIL -Console should use cscript: $($con.runner_exe)" -ForegroundColor Red
    $failures++
} else {
    Write-Host "PASS -Console uses cscript" -ForegroundColor Green
}

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

if ($failures -gt 0) {
    Write-Host "`n$failures case(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host "`nAll dispatch cases passed." -ForegroundColor Green
exit 0
