# =============================================================================
# NIDPS pre-flight check for native Windows. Read-only: it changes nothing.
#   .\check-windows.ps1
#   .\check-windows.ps1 -SnortDir D:\Snort -Port 5000
# Exit code = number of failed checks (0 = ready).
# =============================================================================
param(
    [string]$SnortDir = "C:\Snort",
    [int]$Port = 5000
)
$failures = 0
function Check([bool]$ok, [string]$what, [string]$fix) {
    if ($ok) { Write-Host "  [ OK ] $what" -ForegroundColor Green }
    else {
        Write-Host "  [FAIL] $what" -ForegroundColor Red
        Write-Host "         fix: $fix"
        $script:failures++
    }
}

Write-Host "NIDPS Windows pre-flight" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Check $isAdmin "Running as Administrator (needed for the live Windows firewall)" "open PowerShell with 'Run as administrator'"

$node = Get-Command node -ErrorAction SilentlyContinue
$nodeOk = $false
if ($node) { $nodeOk = ([int]((& node -p "process.versions.node.split('.')[0]") | Out-String).Trim()) -ge 18 }
Check $nodeOk "Node.js 18 or later" "install Node.js LTS from nodejs.org"

$npcap = (Test-Path "$env:SystemRoot\System32\Npcap") -or [bool](Get-Service -Name npcap -ErrorAction SilentlyContinue)
Check $npcap "Npcap installed (packet capture driver)" "install Npcap with 'WinPcap API-compatible mode' ticked"

$snortExe = Join-Path $SnortDir "bin\snort.exe"
Check (Test-Path $snortExe) "Snort installed ($snortExe)" "install Snort 2.9 for Windows, or pass -SnortDir"

$conf = Join-Path $SnortDir "etc\nidps.conf"
Check (Test-Path $conf) "NIDPS Snort configuration ($conf)" ".\setup-snort.ps1 -HomeNet <your network, e.g. 192.168.1.0/24>"

Check ([bool](Get-Process -Name snort -ErrorAction SilentlyContinue)) "Snort is running" ".\start-snort.ps1 -Interface <adapter index>"

$alertLog = Join-Path $SnortDir "log\snort.alert.fast"
Check (Test-Path $alertLog) "Alert log exists ($alertLog)" "start Snort once, or re-run setup-snort.ps1"

$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
$fwOn = [bool]$profiles -and -not ($profiles | Where-Object { -not $_.Enabled })
Check $fwOn "Windows Firewall is on for every profile (Domain, Private, Public)" "Windows Security > Firewall & network protection: turn it on"

$health = $false
try {
    $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Uri "http://localhost:$Port/api/health"
    $health = $r.Content -match '"system":"NIDPS"'
} catch {
    try {
        # HTTPS with a self-signed certificate: any answer on the port is enough here.
        $tcp = New-Object Net.Sockets.TcpClient
        $tcp.Connect("localhost", $Port); $health = $tcp.Connected; $tcp.Close()
    } catch { $health = $false }
}
Check $health "NIDPS is answering on port $Port" "cd backend; npm start   (in an elevated PowerShell)"

$rules = @(Get-NetFirewallRule -DisplayName 'NIDPS-block-*' -ErrorAction SilentlyContinue).Count
Write-Host "  [INFO] NIDPS block rules currently in Windows Firewall: $rules"

Write-Host ""
if ($failures -eq 0) { Write-Host "All 9 checks passed." -ForegroundColor Green }
else { Write-Host "$failures of 9 checks failed." -ForegroundColor Yellow }
exit $failures
