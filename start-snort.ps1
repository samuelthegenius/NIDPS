# Launch Snort IDS inside WSL (Ubuntu-24.04) as root
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   Starting Snort IDS Sensor inside WSL (Ubuntu-24.04)  " -ForegroundColor Cyan
Write-Host "   Interface: eth0 | Log: /var/log/snort/snort.alert.fast" -ForegroundColor Cyan
Write-Host "   Press Ctrl+C to terminate Snort sensor." -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

wsl -d Ubuntu-24.04 -u root bash -c "mkdir -p /var/log/snort && chmod -R 777 /var/log/snort && exec snort -A fast -q -c /etc/snort/snort.conf -i eth0 -l /var/log/snort"
