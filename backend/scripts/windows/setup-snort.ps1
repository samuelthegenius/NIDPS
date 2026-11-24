# =============================================================================
# NIDPS - Snort 2.9 sensor setup on native Windows. Run in an elevated PowerShell.
#
#   .\setup-snort.ps1 -HomeNet 192.168.1.0/24                # lists adapters
#   .\setup-snort.ps1 -HomeNet 192.168.1.0/24 -Interface 3   # also tests the config
#
# Before running: install Npcap (tick "WinPcap API-compatible mode") and
# Snort 2.9 for Windows (default folder C:\Snort). Both come from their
# official websites; this script does not download anything.
#
# It writes a small, self-contained configuration (it does not edit Snort's
# own snort.conf):
#   C:\Snort\etc\nidps.conf     HOME_NET, fast-alert output, NIDPS rules
#   C:\Snort\rules\nidps.rules  the same demo rules as on Linux
#   C:\Snort\log\               where snort.alert.fast is written
# =============================================================================
param(
    [Parameter(Mandatory = $true)][string]$HomeNet,
    [string]$Interface = "",
    [string]$SnortDir = "C:\Snort"
)
$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Run this in PowerShell opened with 'Run as administrator'." -ForegroundColor Red; exit 1 }

if ($HomeNet -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') {
    Write-Host "HomeNet must look like 192.168.1.0/24 (got '$HomeNet')." -ForegroundColor Red; exit 1
}

$snort = Join-Path $SnortDir "bin\snort.exe"
if (-not (Test-Path $snort)) {
    Write-Host "Snort not found at $snort. Install Snort 2.9 for Windows (and Npcap) first, or pass -SnortDir." -ForegroundColor Red
    exit 1
}

$etc = Join-Path $SnortDir "etc"
$rulesDir = Join-Path $SnortDir "rules"
$logDir = Join-Path $SnortDir "log"
foreach ($d in @($etc, $rulesDir, $logDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

Write-Host "[*] Installing NIDPS rules -> $rulesDir\nidps.rules"
$rulesSource = Join-Path $PSScriptRoot "..\snort\nidps.rules"
Copy-Item -Path $rulesSource -Destination (Join-Path $rulesDir "nidps.rules") -Force

Write-Host "[*] Writing $etc\nidps.conf (HOME_NET $HomeNet)"
$conf = @"
# NIDPS minimal Snort configuration (written by setup-snort.ps1; safe to re-run).
ipvar HOME_NET $HomeNet
ipvar EXTERNAL_NET any
config classification: misc-activity,Misc activity,3
config classification: attempted-recon,Attempted Information Leak,2
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: web-application-attack,Web Application Attack,1
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows
preprocessor stream5_global: track_tcp yes, track_udp no, track_icmp no
preprocessor stream5_tcp: policy windows, ports both 22 80 8080
output alert_fast: snort.alert.fast
include $rulesDir\nidps.rules
"@
Set-Content -Path (Join-Path $etc "nidps.conf") -Value $conf -Encoding Ascii

$alertLog = Join-Path $logDir "snort.alert.fast"
if (-not (Test-Path $alertLog)) { New-Item -ItemType File -Path $alertLog | Out-Null }

if ($Interface -eq "") {
    Write-Host ""
    Write-Host "[*] Network adapters (use the Index of the adapter that faces the network):" -ForegroundColor Cyan
    & $snort -W
    Write-Host ""
    Write-Host "Re-run with -Interface <Index> to test the configuration."
    exit 0
}

Write-Host "[*] Testing the configuration on adapter $Interface ..."
& $snort -T -q -c (Join-Path $etc "nidps.conf") -i $Interface -l $logDir
if ($LASTEXITCODE -ne 0) { Write-Host "Snort rejected the configuration (see above)." -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "[+] Snort configuration OK." -ForegroundColor Green
Write-Host "    Start Snort : .\start-snort.ps1 -Interface $Interface"
Write-Host "    backend\.env: SNORT_LOG_PATH=$alertLog"
Write-Host "                  SNORT_INTERFACE=$Interface"
Write-Host "                  NIDPS_FIREWALL=auto   ENABLE_REAL_FIREWALL=true"
Write-Host "    Then check  : .\check-windows.ps1"
