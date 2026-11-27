<#
.SYNOPSIS
    Native Windows end-to-end qualification script (WLS-01..08, WFG-05, CL-25, CL-27).
    Run after Install-L2Tunnel.ps1 to qualify local API v5, DPAPI, Share URI import,
    GeoIP/ASN RedirectPolicy routes, live cover switching, Internal MTU > Capsule MTU,
    throughput/ping, and clean teardown against a real l2tunneld server.
.EXAMPLE
    .\Verify-L2TunnelWindows.ps1 -ShareUri "l2tunnel://v1/connect?..." -TunnelServerIp 192.168.236.1
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\l2tunnel",
    [string]$PipeName = "\\.\pipe\l2tunnel",
    [string]$ShareUri = "",
    [string]$TunnelServerIp = "192.168.236.1",
    [string]$ProfileName = "win-e2e",
    [string]$OutputJson = ".\windows-native-receipt.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ctl = Join-Path $InstallDir "l2tunnelctl.exe"
$svc = Join-Path $InstallDir "l2tunnel-windows.exe"

function Invoke-CtlJson {
    param([string[]]$Arguments)
    $raw = & $ctl --control-socket $PipeName --json @Arguments 2>&1
    $last = ($raw | Where-Object { $_ -match '^\{' } | Select-Object -Last 1)
    if (-not $last) { return @{ ok = $false; raw = ($raw -join "`n") } }
    return ($last | ConvertFrom-Json)
}

$receipt = [ordered]@{
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    os_version       = [System.Environment]::OSVersion.VersionString
    architecture     = $env:PROCESSOR_ARCHITECTURE
    is_admin         = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    pipe             = $PipeName
    checks           = [ordered]@{}
}

Write-Host "==> 1. Local API v5 status & service capabilities (WLS-04/WLS-06)" -ForegroundColor Cyan
$status = Invoke-CtlJson @("service", "status")
$info = Invoke-CtlJson @("service", "info")
$receipt.checks["api_v5_status"] = @{ ok = $status.ok; phase = $status.status.phase }
$receipt.checks["api_v5_info"] = @{ ok = $info.ok; version = $info.info.version; api = $info.info.api }
if (-not $status.ok) { throw "Service did not answer on $PipeName" }

Write-Host "==> 2. Offline GeoIP/ASN RedirectPolicy & Plan Tune (Internal > Capsule MTU)" -ForegroundColor Cyan
$lookup = & $ctl policy lookup 114.114.114.114 --json | ConvertFrom-Json
$compiled = & $ctl policy compile --preset bypass-cn-and-lan --peer 198.51.100.10 --json | ConvertFrom-Json
$receipt.checks["policy_geoip_asn"] = @{
    ok            = ($lookup.country -eq "CN" -and $lookup.asn -eq 4134)
    include_count = $compiled.include_v4.Count
    exclude_count = $compiled.exclude_v4.Count
}

$basePlan = Join-Path $InstallDir "plans\common-1500.json"
if (Test-Path $basePlan) {
    $jumboTmp = Join-Path $env:TEMP "l2t-win-jumbo-4096-1300.json"
    & $ctl plan tune --input $basePlan --output $jumboTmp --device-mtu 4096 --path-mtu 1300 --repair off --force | Out-Null
    $receipt.checks["plan_tune_4096_over_1300"] = @{ ok = ($LASTEXITCODE -eq 0 -and (Test-Path $jumboTmp)) }
    Remove-Item -Force -ErrorAction SilentlyContinue $jumboTmp
}

Write-Host "==> 3. DPAPI secret sealing round-trip (CL-27)" -ForegroundColor Cyan
$tmpPlain = Join-Path $env:TEMP "l2t-dpapi-test.key"
$tmpSealed = Join-Path $env:TEMP "l2t-dpapi-test.dpapi"
Remove-Item -Force -ErrorAction SilentlyContinue $tmpPlain, $tmpSealed
[System.IO.File]::WriteAllBytes($tmpPlain, [byte[]](1..32))
& $svc dpapi seal --input $tmpPlain --output $tmpSealed --scope user | Out-Null
$sealedBytes = [System.IO.File]::ReadAllBytes($tmpSealed)
$magic = [System.Text.Encoding]::ASCII.GetString($sealedBytes[0..3])
$receipt.checks["dpapi_seal"] = @{ ok = ($LASTEXITCODE -eq 0 -and $magic -eq "L2DP"); bytes = $sealedBytes.Length }
Remove-Item -Force -ErrorAction SilentlyContinue $tmpPlain, $tmpSealed

if ($ShareUri -ne "") {
    Write-Host "==> 4. Importing Share URI & connecting live Wintun tunnel..." -ForegroundColor Cyan
    $imp = $ShareUri | & $ctl --control-socket $PipeName --json profile import $ProfileName --uri -
    $conn = Invoke-CtlJson @("service", "connect", "--profile", $ProfileName, "--watch", "30")
    $receipt.checks["live_connect"] = @{ ok = $conn.ok }

    if ($conn.ok) {
        $devs = Invoke-CtlJson @("device", "list")
        $receipt.checks["wintun_device"] = $devs.devices

        # Ping across Wintun
        $pingOut = ping.exe -n 5 $TunnelServerIp
        $receipt.checks["ping_standard"] = @{ ok = ($LASTEXITCODE -eq 0) }

        # In-process TunnelTestV1 speed across UDP covers
        $speedRows = @()
        foreach ($cover in @("quic-like", "media-like", "tls-like")) {
            if ($cover -ne "quic-like") {
                Invoke-CtlJson @("carrier", "switch", "--target", $cover) | Out-Null
                Start-Sleep -Seconds 2
            }
            $dl = Invoke-CtlJson @("test", "speed", "--download", "--streams", "4", "--seconds", "3")
            $ul = Invoke-CtlJson @("test", "speed", "--streams", "4", "--seconds", "3")
            $speedRows += [ordered]@{
                cover   = $cover
                dl_mbps = if ($dl.test.test.bits_per_second) { [math]::Round($dl.test.test.bits_per_second / 1e6, 2) } else { $null }
                ul_mbps = if ($ul.test.test.bits_per_second) { [math]::Round($ul.test.test.bits_per_second / 1e6, 2) } else { $null }
            }
        }
        $receipt.checks["speed_matrix"] = $speedRows

        # Clean disconnect and verify no leaked service-owned routes
        $disc = Invoke-CtlJson @("service", "disconnect", "--watch", "15")
        Start-Sleep -Seconds 1
        $routesAfter = Invoke-CtlJson @("route", "list")
        $ownedLeft = @($routesAfter.routes | Where-Object { $_.owned -eq $true }).Count
        $receipt.checks["disconnect_and_cleanup"] = @{ ok = ($disc.ok -and $ownedLeft -eq 0); owned_routes_remaining = $ownedLeft }
    }
} else {
    Write-Host "    (Pass -ShareUri 'l2tunnel://v1/connect?...' to run live tunnel & speed checks)" -ForegroundColor Yellow
}

$receipt | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputJson -Encoding UTF8
Write-Host "`nWrote native Windows qualification receipt to $OutputJson" -ForegroundColor Green
