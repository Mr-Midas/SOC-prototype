<#
.SYNOPSIS
    Host-side orchestrator for the Arbiterion malware analysis VM (VirtualBox).

.DESCRIPTION
    Drives a fully automatic lifecycle:
      New-VM      detect ISO, create the VM, run VBoxManage unattended install (zero clicks),
                  boot it, and wait until the guest is ready.
      Provision   stage Sysmon/Python wheels/LuaJIT/collector into a temp shared folder,
                  run provision-vm.ps1 inside the guest, then remove the share.
      Snapshot    take the "Before-Detonation" snapshot.
      Detonate    stage the sample, run it via LuaJIT in the guest, observe for N seconds,
                  and take a screenshot. Host-only network => no internet path.
      Export      query host PostgreSQL for the VM's alerts, write JSON+markdown to
                  Desktop\arbiterion-analysis-<ts>\ and capture a VM screenshot.
                  (REQUIRED before Rollback.)
      Rollback    refuse unless an export newer than the last detonation exists, then
                  restore the Before-Detonation snapshot.
      Remove      delete the VM and all its media.

.PARAMETER Command
    One of: New-VM, Provision, Snapshot, Detonate, Export, Rollback, Remove, Status.

.EXAMPLE
    .\scripts\analysis-vm.ps1 New-VM -IsoPath C:\Users\me\Downloads\Win11.iso
    .\scripts\analysis-vm.ps1 Provision
    .\scripts\analysis-vm.ps1 Snapshot
    .\scripts\analysis-vm.ps1 Detonate -SamplePath C:\samples\loader.lua -Seconds 90
    .\scripts\analysis-vm.ps1 Export
    .\scripts\analysis-vm.ps1 Rollback
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("New-VM", "Provision", "Snapshot", "Detonate", "Export", "Rollback", "Remove", "Status")]
    [string]$Command,

    [string]$IsoPath,

    [string]$ProductKey,

    [int]$ImageIndex = 0,

    [switch]$SkipUefi,

    [string]$SamplePath,

    [int]$Seconds = 90
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------- config
$VBox        = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$VmName      = "Arbiterion-Analysis"
$VmIp        = "192.168.56.101"
$ShareName   = "ArbiterionStaging"
$HostId      = "Arbiterion-Analysis"
$AdminUser   = "analyst"
$WorkDir     = Join-Path $env:TEMP "arbiterion-vm-analysis"
$CredFile    = Join-Path $WorkDir "credentials.json"
$StateFile   = Join-Path $WorkDir "state.json"
$RepoRoot    = Split-Path -Parent $PSScriptRoot
$PythonUrl   = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
$LuaJitUrl   = "https://gitlab.com/windows-luajit/windows-luajit-installer/uploads/0a63f974de75d0568feafbb123d04ff6/luajit-installer-1.0.8.exe"

function Test-Prerequisites {
    if (-not (Test-Path $VBox)) {
        throw "VBoxManage not found at $VBox. Install VirtualBox 7.2+ and re-run."
    }
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Not running as Administrator: firewall rule and some VBox operations may fail."
    }
}

function Get-HostOnlyIp {
    $out = & $VBox list hostonlyifs 2>$null
    $ip = $null
    for ($i = 0; $i -lt $out.Count; $i++) {
        if ($out[$i] -match "^Name:\s+(.+)") { $name = $Matches[1] }
        if ($out[$i] -match "^IPAddress:\s+([\d\.]+)") { $ip = $Matches[1]; break }
    }
    if (-not $ip) { $ip = "192.168.56.1" }
    Write-Host "Host-only adapter IP: $ip"
    return $ip
}

function Get-VmState {
    $out = & $VBox showvminfo $VmName --machinereadable 2>$null
    if ($LASTEXITCODE -ne 0) { return "notfound" }
    return ($out | Select-String '^VMState="(.+)"').Matches[0].Groups[1].Value
}

function Assert-VmExists {
    if ((Get-VmState) -eq "notfound") { throw "VM '$VmName' does not exist. Run New-VM first." }
}

function Get-AdminPassword {
    if (Test-Path $CredFile) {
        $creds = Get-Content $CredFile -Raw | ConvertFrom-Json
        return $creds.admin_password
    }
    return $null
}

function Save-AdminPassword {
    param([string]$Password)
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    @{ admin_user = $AdminUser; admin_password = $Password; host_id = $HostId; created_at = (Get-Date).ToUniversalTime().ToString("o") } |
        ConvertTo-Json | Set-Content $CredFile -Encoding UTF8
}

function Get-TenantSecret {
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $py) { throw "Python not found on the HOST; cannot read tenant webhook secret." }
    $secret = & $py (Join-Path $PSScriptRoot "export-results.py") secret 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($secret)) {
        throw "Failed to read tenant webhook secret. Is the host API stack + postgres running?"
    }
    return $secret.Trim()
}

function Wait-VmReady {
    param([int]$TimeoutSeconds = 1800)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    Write-Host "Waiting for guest to finish installing and log in (up to $TimeoutSeconds s)..."
    while ((Get-Date) -lt $deadline) {
        $state = Get-VmState
        if ($state -eq "notfound") { throw "VM disappeared." }
        if ($state -match "poweroff|aborted|saved|guru") {
            Write-Warning "VM state is '$state' while waiting. Trying one more boot..."
            if ($state -match "poweroff|aborted|saved") {
                & $VBox startvm $VmName --type headless 2>&1 | Out-Null
            }
        }
        $props = & $VBox guestproperty get $VmName "/VirtualBox/GuestInfo/OS/LoggedInUsers" 2>&1
        $additions = & $VBox guestproperty get $VmName "/VirtualBox/GuestAdditions/Version" 2>&1
        if ($additions -match "Value:\s*(\d+\.)" -and $props -match "Value:\s*\S") {
            Write-Host "Guest logged in with Guest Additions $($Matches[1])."
            return
        }
        Start-Sleep -Seconds 15
    }
    throw "Timed out waiting for the guest to become ready."
}

function Invoke-GuestRun {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Args,
        [int]$Timeout = 600
    )
    $password = Get-AdminPassword
    if (-not $password) { throw "No stored credentials. Run New-VM first." }
    & $VBox guestcontrol $VmName run --username $AdminUser --password $password --timeout $Timeout --exe $Exe -- $Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "guestcontrol run failed for $Exe (exit $LASTEXITCODE)."
    }
}

function Invoke-GuestStart {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Args
    )
    $password = Get-AdminPassword
    if (-not $password) { throw "No stored credentials. Run New-VM first." }
    & $VBox guestcontrol $VmName start --username $AdminUser --password $password --exe $Exe -- $Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "guestcontrol start failed for $Exe (exit $LASTEXITCODE)."
    }
}

function Invoke-GuestMountShare {
    param([string]$Share)
    Invoke-GuestRun -Exe "C:\Windows\System32\cmd.exe" -Args @("/c net use Z: \\vboxsrv\$Share /persistent:no")
}

function Invoke-GuestUnmountShare {
    try { Invoke-GuestRun -Exe "C:\Windows\System32\cmd.exe" -Args @("/c net use Z: /delete /y >nul 2>&1") } catch { Write-Warning "Unmount Z: failed: $_" }
}

function Add-SharedFolder {
    param([string]$HostPath, [switch]$Transient)
    $sfArgs = @("sharedfolder", "add", $VmName, "--name", $ShareName, "--hostpath", $HostPath, "--automount")
    if ($Transient) { $sfArgs += "--transient" }
    & $VBox @sfArgs 2>$null
    if ($LASTEXITCODE -ne 0) {
        & $VBox sharedfolder remove $VmName --name $ShareName 2>$null
        & $VBox @sfArgs 2>$null
    }
    if ($LASTEXITCODE -ne 0) { throw "Failed to add shared folder $ShareName." }
}

function Remove-SharedFolder {
    & $VBox sharedfolder remove $VmName --name $ShareName 2>$null
}

function Invoke-Download {
    param([string]$Url, [string]$Dest, [int]$Retries = 3)
    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        try {
            $ProgressPreference = "SilentlyContinue"
            Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -TimeoutSec 300
            if ((Get-Item $Dest).Length -gt 0) { return $true }
        } catch {
            Write-Warning "Download attempt $attempt/$Retries failed for $Url : $($_.Exception.Message)"
            Start-Sleep -Seconds 3
        }
    }
    return $false
}

# ---------------------------------------------------------------- commands
function New-AnalysisVm {
    param([string]$Iso, [string]$Key, [int]$ImageIndex = 0, [switch]$SkipUefi)
    Test-Prerequisites

    if ((Get-VmState) -ne "notfound") {
        throw "VM '$VmName' already exists. Use Remove-Vm first (or Provision/Detonate)."
    }
    if (-not $Iso) { throw "-IsoPath is required." }
    if (-not (Test-Path $Iso)) { throw "ISO not found: $Iso" }

    Write-Host "Detecting OS from ISO..."
    $detect = & $VBox unattended detect --iso="$Iso" --machine-readable 2>&1
    if ($LASTEXITCODE -ne 0) { throw "unattended detect failed: $detect" }
    $detectText = ($detect -join "`n")
    Write-Host $detectText
    $osType = ($detectText | Select-String 'OSType:\s*(\S+)' -AllMatches).Matches | Select-Object -First 1
    $osType = if ($osType) { $osType.Groups[1].Value } else { "Windows11_64" }
    $isWin11 = $detectText -match "Windows 11" -or $osType -match "^Windows11"

    if ($ImageIndex -eq 0 -and $isWin11) {
        Write-Host "Windows 11 ISO: defaulting to image index 6 (Windows 11 Pro) to avoid Home OOBE update hang."
        $ImageIndex = 6
    }

    $password = "Arbiter!" + (-join ((Get-Random -Minimum 100000 -Maximum 999999).ToString()) + "aA1")
    Save-AdminPassword -Password $password

    Write-Host "Creating VM '$VmName' (os=$osType)..."
    & $VBox createvm --name $VmName --ostype $osType --register 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "createvm failed." }

    $vmDir = Split-Path -Parent (& $VBox showvminfo $VmName --machinereadable 2>&1 | Select-String '^CfgFile="(.+)"').Matches[0].Groups[1].Value

    & $VBox modifyvm $VmName --memory 4096 --cpus 2 --vram 128 `
        --graphicscontroller vmsvga --nic1 nat `
        --nic2 hostonly --host-only-adapter2 "VirtualBox Host-Only Ethernet Adapter" `
        --audio none --usb off --ioapic on 2>&1
    if ($LASTEXITCODE -ne 0) { throw "modifyvm base settings failed." }

    if ($isWin11 -and -not $SkipUefi) {
        Write-Host "Windows 11 detected -> enabling EFI and TPM 2.0."
        & $VBox modifyvm $VmName --firmware efi --tpm-type 2.0 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "TPM 2.0 unavailable; falling back to EFI-only (unattended install bypasses the TPM/SecureBoot checks)."
            & $VBox modifyvm $VmName --firmware efi 2>&1
        }
    }

    $diskPath = Join-Path $vmDir "$VmName.vdi"
    & $VBox createmedium disk --filename $diskPath --size 61440 --format VDI 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "createmedium failed." }

    & $VBox storagectl $VmName --name "SATA" --add sata --controller IntelAhci --portcount 2 --bootable on 2>&1 | Out-Null
    & $VBox storageattach $VmName --storagectl "SATA" --port 0 --device 0 --type hdd --medium $diskPath 2>&1 | Out-Null
    & $VBox storagectl $VmName --name "IDE" --add ide --controller PIIX4 2>&1 | Out-Null
    & $VBox storageattach $VmName --storagectl "IDE" --port 0 --device 0 --type dvddrive --medium $Iso 2>&1 | Out-Null

    Write-Host "Starting unattended install (this takes a while)..."
    $unArgs = @(
        "unattended", "install", $VmName,
        "--iso=$Iso",
        "--user=$AdminUser",
        "--user-password=$password",
        "--full-user-name=Analysis Analyst",
        "--image-index=$ImageIndex",
        "--install-additions",
        "--locale=en_US", "--country=US",
        "--start-vm=headless"
    )
    if ($Key) { $unArgs += "--key=$Key" }
    $out = & $VBox $unArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "unattended install failed: $out" }
    Write-Host $out

    Write-Host "Allowing host firewall for host-only subnet -> port 8000."
    try {
        New-NetFirewallRule -DisplayName "Arbiterion VM Analysis" -Direction Inbound -Protocol TCP `
            -LocalPort 8000 -RemoteAddress "192.168.56.0/24" -Action Allow -ErrorAction Stop | Out-Null
    } catch { Write-Warning "Firewall rule not applied: $_" }

    Wait-VmReady
    Write-Host "Install complete. Removing the NAT install NIC (Win11 Home OOBE needs internet during setup)."
    & $VBox controlvm $VmName poweroff 2>&1
    Start-Sleep -Seconds 5
    & $VBox modifyvm $VmName --nic1 none 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Failed to disable install NIC." }
    & $VBox startvm $VmName --type headless 2>&1 | Out-Null
    Start-Sleep -Seconds 8
    Write-Host "`nVM ready (host-only only). Next: .\scripts\analysis-vm.ps1 Provision"
}

function Initialize-Staging {
    param([string]$Kind) # "provision" or "detonate"
    $dir = Join-Path $WorkDir "staging-$Kind"
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return $dir
}

function New-ProvisionStaging {
    $staging = Initialize-Staging "provision"

    New-Item -ItemType Directory -Force -Path (Join-Path $staging "sysmon") | Out-Null
    Copy-Item (Join-Path $RepoRoot "sysmon\Sysmon64.exe") (Join-Path $staging "sysmon\Sysmon64.exe") -Force
    Copy-Item (Join-Path $RepoRoot "sysmon\sysmonconfig-export.xml") (Join-Path $staging "sysmon\sysmonconfig-export.xml") -Force
    Copy-Item (Join-Path $RepoRoot "collector.py") (Join-Path $staging "collector.py") -Force
    Copy-Item (Join-Path $RepoRoot "requirements.txt") (Join-Path $staging "requirements.txt") -Force

    New-Item -ItemType Directory -Force -Path (Join-Path $staging "python") | Out-Null
    $pyInstaller = Join-Path $staging "python\python-installer.exe"
    if (-not (Test-Path $pyInstaller)) {
        Write-Host "Downloading Python 3.11.9 installer (~25 MB)..."
        if (-not (Invoke-Download -Url $PythonUrl -Dest $pyInstaller)) { throw "Python download failed." }
    }

    New-Item -ItemType Directory -Force -Path (Join-Path $staging "wheels") | Out-Null
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $py) { throw "Python not found on the HOST; needed to download pip wheels." }
    Write-Host "Downloading httpx + python-dotenv wheels (offline install in guest)..."
    Push-Location $staging
    try {
        & $py -m pip download --no-deps --dest (Join-Path $staging "wheels") httpx python-dotenv 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "pip download failed (exit $LASTEXITCODE)." }
    } finally { Pop-Location }

    New-Item -ItemType Directory -Force -Path (Join-Path $staging "luajit") | Out-Null
    $ljInstaller = Join-Path $staging "luajit\luajit-installer-1.0.8.exe"
    if (-not (Test-Path $ljInstaller)) {
        Write-Host "Downloading LuaJIT 2.1 Windows installer..."
        if (-not (Invoke-Download -Url $LuaJitUrl -Dest $ljInstaller)) {
            Write-Warning "LuaJIT download failed. Place a LuaJIT Windows installer/exe (named *.exe) into '$staging\luajit\' and re-run Provision."
            throw "LuaJIT installer not available."
        }
    }

    return $staging
}

function Provision-Vm {
    Assert-VmExists
    Test-Prerequisites
    $secret = Get-TenantSecret
    $hostIp = Get-HostOnlyIp

    $staging = New-ProvisionStaging
    Add-SharedFolder -HostPath $staging
    try {
        Invoke-GuestMountShare -Share $ShareName
        $ljPath = (Join-Path $staging "luajit\luajit-installer-1.0.8.exe")

        $psExe = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $psArgs = @(
            "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", "Z:\provision-vm.ps1",
            "-Endpoint", "http://$hostIp`:8000/api/ingest/endpoint-event",
            "-LoginUrl", "http://$hostIp`:8000/api/login",
            "-Secret", $secret,
            "-Username", "admin@arbiterion.local",
            "-Password", "ChangeMe123!",
            "-StagingShare", $ShareName,
            "-HostId", $HostId
        )
        Write-Host "Running provisioning inside the guest (streaming output)..."
        Invoke-GuestRun -Exe $psExe -Args $psArgs -Timeout 1800
    } finally {
        Invoke-GuestUnmountShare
        Remove-SharedFolder
        Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Provisioning share removed; staging material deleted."
    }
    Write-Host "`nProvisioned. Next: .\scripts\analysis-vm.ps1 Snapshot"
}

function Snapshot-Vm {
    Assert-VmExists
    $ts = Get-Date -Format "yyyyMMdd-HHmmss"
    & $VBox snapshot $VmName take "Before-Detonation-$ts" --description "Clean state before detonation $ts" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "snapshot failed." }
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    @{ detonation_started = $null; snapshot = "Before-Detonation-$ts"; snapshot_ts = $ts } | ConvertTo-Json | Set-Content $StateFile -Encoding UTF8
    Write-Host "Snapshot 'Before-Detonation-$ts' taken."
}

function Detonate-Sample {
    param([string]$Sample, [int]$ObserveSeconds)
    Assert-VmExists
    if (-not $Sample) { throw "-SamplePath is required." }
    if (-not (Test-Path $Sample)) { throw "Sample not found: $Sample" }
    if (-not (Test-Path $StateFile)) { throw "No snapshot state found. Run Snapshot first." }

    Write-Host "`n=== DETONATION CONFIRMATION ===" -ForegroundColor Yellow
    Write-Host "You are about to run the sample '$Sample' inside the isolated VM '$VmName'." -ForegroundColor Yellow
    Write-Host "  - Host-only network: NO internet path from the VM." -ForegroundColor Yellow
    Write-Host "  - The sample will block on its connectivity check (microsoft.com) and never reach C2." -ForegroundColor Yellow
    Write-Host "  - Alerts will be collected by Sysmon/collector and persisted in host PostgreSQL." -ForegroundColor Yellow
    $confirm = Read-Host "Type 'DETONATE' to continue"
    if ($confirm -ne "DETONATE") { Write-Host "Aborted."; return }

    $state = Get-Content $StateFile -Raw | ConvertFrom-Json
    $staging = Initialize-Staging "detonate"
    try {
        Copy-Item $Sample (Join-Path $staging (Split-Path $Sample -Leaf)) -Force
        Add-SharedFolder -HostPath $staging -Transient
        Invoke-GuestMountShare -Share $ShareName
        $leaf = Split-Path $Sample -Leaf
        $copyCmd = "/c copy /Y Z:\$leaf C:\Users\$AdminUser\Desktop\$leaf"
        Invoke-GuestRun -Exe "C:\Windows\System32\cmd.exe" -Args @($copyCmd)

        $ljPath = Get-LuaJitGuestPath
        Write-Host "Detonating with $ljPath ..."
        Invoke-GuestStart -Exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Args @(
            "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-Command", "Set-Location C:\Users\$AdminUser\Desktop; & '$ljPath' '$leaf' > C:\Users\$AdminUser\Desktop\sample-output.txt 2>&1"
        )

        Write-Host "Observing for $ObserveSeconds seconds..."
        Start-Sleep -Seconds $ObserveSeconds

        # Capture process list + screenshot for the report
        $psCmd = "Get-Process | Where-Object { `$_.Path -match 'luajit|$leaf' } | Select-Object Id,ProcessName,Path | ConvertTo-Json"
        $psOut = Invoke-GuestRun -Exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Args @("-NoProfile", "-Command", $psCmd) -Timeout 60
        Write-Host "Guest processes:"
        Write-Host $psOut
    } finally {
        Invoke-GuestUnmountShare
        Remove-SharedFolder
        Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Detonation staging removed."
    }
    $state | Add-Member -NotePropertyName detonation_started -NotePropertyValue ((Get-Date).ToUniversalTime().ToString("o")) -Force
    $state | ConvertTo-Json | Set-Content $StateFile -Encoding UTF8
    Write-Host "`nDetonation complete. Next: .\scripts\analysis-vm.ps1 Export (required before Rollback)"
}

function Get-LuaJitGuestPath {
    # Stored from provisioning; fall back to common location.
    $psCmd = "Get-ChildItem 'C:\Program Files\LuaJIT*' -Filter luajit.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName"
    $out = Invoke-GuestRun -Exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Args @("-NoProfile", "-Command", $psCmd) -Timeout 120
    $path = ($out | Select-Object -Last 1 | Where-Object { $_ -match "luajit.exe" } | Out-String).Trim()
    if (-not $path) { throw "Could not locate luajit.exe in the guest." }
    return $path
}

function Export-Results {
    Assert-VmExists
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $py) { throw "Python not found on the HOST; cannot run export." }

    $outDir = Join-Path ([Environment]::GetFolderPath("Desktop")) ("arbiterion-analysis-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
    Write-Host "Exporting alerts for host '$HostId'..."
    & $py (Join-Path $PSScriptRoot "export-results.py") export --host $HostId --out $outDir 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Export failed." }

    $screenshot = Join-Path $outDir "screenshot.png"
    & $VBox controlvm $VmName screenshotpng $screenshot 2>&1 | Out-Null
    if (Test-Path $screenshot) { Write-Host "Screenshot saved: $screenshot" }

    if (Test-Path $StateFile) {
        $state = Get-Content $StateFile -Raw | ConvertFrom-Json
        $state | Add-Member -NotePropertyName last_export -NotePropertyValue ((Get-Date).ToUniversalTime().ToString("o")) -Force
        $state | Add-Member -NotePropertyName last_export_dir -NotePropertyValue $outDir -Force
        $state | ConvertTo-Json | Set-Content $StateFile -Encoding UTF8
    }
    Write-Host "`nExported to $outDir. Next: .\scripts\analysis-vm.ps1 Rollback"
}

function Rollback-Vm {
    Assert-VmExists
    if (-not (Test-Path $StateFile)) { throw "No snapshot state. Run Snapshot then Detonate first." }
    $state = Get-Content $StateFile -Raw | ConvertFrom-Json

    if (-not $state.last_export) {
        throw "No export found. Run Export first - results would be lost on rollback."
    }
    if ($state.detonation_started) {
        $started = [datetime]::Parse($state.detonation_started)
        $exported = [datetime]::Parse($state.last_export)
        if ($exported -lt $started) {
            throw "Last export predates the last detonation. Run Export again before rollback."
        }
    }

    Write-Host "Powering off VM and restoring snapshot '$($state.snapshot)'..."
    & $VBox controlvm $VmName poweroff 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    & $VBox snapshot $VmName restore $state.snapshot 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "snapshot restore failed." }
    Write-Host "Rollback complete. VM is clean again (state of '$($state.snapshot)')."
    Write-Host "Start it anytime with: VBoxManage startvm $VmName --type headless"
}

function Remove-Vm {
    $state = Get-VmState
    if ($state -ne "notfound") {
        & $VBox controlvm $VmName poweroff 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        & $VBox unregistervm $VmName --delete 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "unregistervm failed." }
    }
    Remove-Item (Join-Path $WorkDir "staging-provision") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $WorkDir "staging-detonate") -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "VM removed (media deleted)."
}

function Show-Status {
    $state = Get-VmState
    Write-Host "VM: $VmName -> state: $state"
    if (Test-Path $StateFile) {
        Get-Content $StateFile -Raw
    } else {
        Write-Host "No run state yet."
    }
}

# ---------------------------------------------------------------- dispatch
if ($Command) {
    switch ($Command) {
        "New-VM"    { New-AnalysisVm -Iso $IsoPath -Key $ProductKey -ImageIndex $ImageIndex -SkipUefi:$SkipUefi }
        "Provision" { Provision-Vm }
        "Snapshot"  { Snapshot-Vm }
        "Detonate"  { Detonate-Sample -Sample $SamplePath -ObserveSeconds $Seconds }
        "Export"    { Export-Results }
        "Rollback"  { Rollback-Vm }
        "Remove"    { Remove-Vm }
        "Status"    { Show-Status }
    }
}
