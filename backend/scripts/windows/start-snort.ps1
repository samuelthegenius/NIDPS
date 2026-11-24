# Start the Snort sensor on native Windows (after setup-snort.ps1).
#   .\start-snort.ps1 -Interface 3          # adapter Index from: C:\Snort\bin\snort.exe -W
# Alerts go to C:\Snort\log\snort.alert.fast. Ctrl+C stops Snort.
# (No "-A fast" here: it would override the config and write to a file called "alert".)
param(
    [Parameter(Mandatory = $true)][string]$Interface,
    [string]$SnortDir = "C:\Snort"
)
$snort = Join-Path $SnortDir "bin\snort.exe"
$conf = Join-Path $SnortDir "etc\nidps.conf"
$logDir = Join-Path $SnortDir "log"
if (-not (Test-Path $snort)) { Write-Host "Snort not found at $snort." -ForegroundColor Red; exit 1 }
if (-not (Test-Path $conf)) { Write-Host "$conf missing. Run .\setup-snort.ps1 first." -ForegroundColor Red; exit 1 }

Write-Host "NIDPS Snort sensor | adapter $Interface | alerts: $logDir\snort.alert.fast | Ctrl+C to stop" -ForegroundColor Cyan
& $snort -q -c $conf -i $Interface -l $logDir
exit $LASTEXITCODE
