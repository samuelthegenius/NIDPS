# Start the Snort sensor inside WSL (Windows development / demo machine).
#   .\start-snort.ps1                       # Ubuntu-24.04, eth0
#   .\start-snort.ps1 -Distro Ubuntu-24.04 -Interface eth0
param(
    [string]$Distro = "Ubuntu-24.04",
    [string]$Interface = "eth0"
)

Write-Host "NIDPS Snort sensor in WSL ($Distro) | interface: $Interface" -ForegroundColor Cyan
Write-Host "Alerts: /var/log/snort/snort.alert.fast | Ctrl+C to stop" -ForegroundColor Cyan

wsl -d $Distro -u root -- bash -c "mkdir -p /var/log/snort && exec snort -A fast -q -c /etc/snort/snort.conf -i '$Interface' -l /var/log/snort"
