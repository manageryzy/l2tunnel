#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs l2tunnel Windows service (multi-profile daemon mode), GUI, CLI,
    WLS-08 admin-only directory ACLs, and the l2tunnel:// Share URI handler.
.EXAMPLE
    .\Install-L2Tunnel.ps1 -WintunDll C:\Downloads\wintun.dll -WintunSha256 <64-hex>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$InstallDir = "$env:ProgramFiles\l2tunnel",

    [Parameter(Mandatory = $false)]
    [string]$StateDir = "$env:ProgramData\l2tunnel\state",

    [Parameter(Mandatory = $false)]
    [string]$WintunDll = "",

    [Parameter(Mandatory = $false)]
    [string]$WintunSha256 = "",

    [Parameter(Mandatory = $false)]
    [string]$DefaultAddress = "10.236.0.2/30",

    [Parameter(Mandatory = $false)]
    [string]$PipeName = "\\.\pipe\l2tunnel"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BundleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path (Join-Path $BundleRoot "l2tunnel-windows.exe"))) {
    throw "l2tunnel-windows.exe not found next to Install-L2Tunnel.ps1 ($BundleRoot)"
}
if ($WintunDll -eq "") {
    $WintunDll = Join-Path $BundleRoot "wintun.dll"
}
if (-not (Test-Path $WintunDll -PathType Leaf)) {
    throw "Wintun DLL not found at $WintunDll. Download official signed wintun.dll (amd64) from https://www.wintun.net/ first."
}

$actualHash = (Get-FileHash -Path $WintunDll -Algorithm SHA256).Hash.ToLowerInvariant()
if ($WintunSha256 -ne "") {
    if ($actualHash -ne $WintunSha256.ToLowerInvariant()) {
        throw "Wintun DLL SHA-256 mismatch! Expected $($WintunSha256.ToLowerInvariant()), got $actualHash"
    }
} else {
    Write-Host "Computed Wintun DLL SHA-256: $actualHash" -ForegroundColor Yellow
    $WintunSha256 = $actualHash
}

Write-Host "==> Creating directories with WLS-08 administrator-only write ACLs..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

# Lock down StateDir: SYSTEM + BUILTIN\Administrators ONLY (no non-admin read or write).
& icacls.exe $StateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to harden ACL on $StateDir" }

# Lock down InstallDir: SYSTEM + BUILTIN\Administrators Full Control; Interactive Users Read & Execute only.
& icacls.exe $InstallDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-4:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to harden ACL on $InstallDir" }

Write-Host "==> Copying binaries, plans, and verified wintun.dll..." -ForegroundColor Cyan
foreach ($file in @("l2tunnel-windows.exe", "l2tunnel-windows-gui.exe", "l2tunnelctl.exe", "Uninstall-L2Tunnel.ps1", "Verify-L2TunnelWindows.ps1")) {
    $src = Join-Path $BundleRoot $file
    if (Test-Path $src) {
        Copy-Item -Force -Path $src -Destination (Join-Path $InstallDir $file)
    }
}
$plansSrc = Join-Path $BundleRoot "plans"
if (Test-Path $plansSrc) {
    Copy-Item -Recurse -Force -Path $plansSrc -Destination (Join-Path $InstallDir "plans")
}
$installedDll = Join-Path $InstallDir "wintun.dll"
Copy-Item -Force -Path $WintunDll -Destination $installedDll

# Re-verify SHA-256 after copy
$copiedHash = (Get-FileHash -Path $installedDll -Algorithm SHA256).Hash.ToLowerInvariant()
if ($copiedHash -ne $WintunSha256.ToLowerInvariant()) {
    throw "Post-copy Wintun DLL SHA-256 verification failed!"
}

Write-Host "==> Registering l2tunnel:// Share URI protocol handler..." -ForegroundColor Cyan
$guiExe = Join-Path $InstallDir "l2tunnel-windows-gui.exe"
$regBase = "Registry::HKEY_CLASSES_ROOT\l2tunnel"
New-Item -Path "$regBase\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path $regBase -Name "(default)" -Value "URL:l2tunnel Profile Share Link"
Set-ItemProperty -Path $regBase -Name "URL Protocol" -Value ""
Set-ItemProperty -Path "$regBase\shell\open\command" -Name "(default)" -Value "`"$guiExe`" `"%1`""

Write-Host "==> Installing and starting l2tunnel Windows service (multi-profile daemon)..." -ForegroundColor Cyan
$svcExe = Join-Path $InstallDir "l2tunnel-windows.exe"
$existing = Get-Service -Name "l2tunnel" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "    Existing l2tunnel service found; uninstalling before reinstall..." -ForegroundColor Yellow
    & $svcExe service uninstall
    Start-Sleep -Seconds 2
}

& $svcExe service install `
    --state-dir $StateDir `
    --wintun-dll $installedDll `
    --wintun-sha256 $WintunSha256 `
    --address $DefaultAddress `
    --pipe $PipeName
if ($LASTEXITCODE -ne 0) { throw "l2tunnel-windows service install failed ($LASTEXITCODE)" }

& $svcExe service start
if ($LASTEXITCODE -ne 0) { throw "l2tunnel-windows service start failed ($LASTEXITCODE)" }

Write-Host "==> Verifying local API v5 named pipe health..." -ForegroundColor Cyan
$ctlExe = Join-Path $InstallDir "l2tunnelctl.exe"
& $ctlExe --control-socket $PipeName service status
& $ctlExe --control-socket $PipeName service info

Write-Host "`nl2tunnel installed and running!" -ForegroundColor Green
Write-Host "  GUI:      $guiExe"
Write-Host "  CLI:      $ctlExe --control-socket $PipeName service status"
Write-Host "  StateDir: $StateDir"
Write-Host "  Logs:     $(Join-Path $StateDir 'service.log') (and Windows Event Viewer -> Application -> l2tunnel)"
