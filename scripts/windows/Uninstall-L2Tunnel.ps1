#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stops and removes the l2tunnel Windows service and l2tunnel:// URI handler.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\l2tunnel",
    [string]$StateDir = "$env:ProgramData\l2tunnel\state",
    [switch]$PurgeState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$svcExe = Join-Path $InstallDir "l2tunnel-windows.exe"
if (Test-Path $svcExe) {
    Write-Host "==> Uninstalling l2tunnel Windows service..." -ForegroundColor Cyan
    & $svcExe service uninstall
    Start-Sleep -Seconds 1
}

Write-Host "==> Removing l2tunnel:// protocol handler..." -ForegroundColor Cyan
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\l2tunnel" -Recurse -Force -ErrorAction SilentlyContinue

if (Test-Path $InstallDir) {
    Write-Host "==> Removing $InstallDir..." -ForegroundColor Cyan
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($PurgeState -and (Test-Path $StateDir)) {
    Write-Host "==> Purging state directory $StateDir..." -ForegroundColor Cyan
    Remove-Item -Path $StateDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "l2tunnel uninstalled." -ForegroundColor Green
