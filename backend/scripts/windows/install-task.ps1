# =============================================================================
# Optional: start NIDPS (and Snort) automatically, elevated, when you sign in.
# Run in an elevated PowerShell.
#   .\install-task.ps1                          # NIDPS only
#   .\install-task.ps1 -SnortInterface 3        # NIDPS + Snort on adapter 3
#   .\install-task.ps1 -Remove                  # remove both tasks
# Console output is not shown when started this way; use "npm start" in a
# window for demos, and this for an always-on machine.
# =============================================================================
param(
    [string]$SnortInterface = "",
    [string]$SnortDir = "C:\Snort",
    [switch]$Remove
)
$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Run this in PowerShell opened with 'Run as administrator'." -ForegroundColor Red; exit 1 }

if ($Remove) {
    foreach ($name in @("NIDPS", "NIDPS-Snort")) {
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
            Write-Host "Removed task $name"
        }
    }
    exit 0
}

$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { Write-Host "node.exe not found on PATH." -ForegroundColor Red; exit 1 }
$backend = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$user = "$env:USERDOMAIN\$env:USERNAME"

$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

$action = New-ScheduledTaskAction -Execute $node -Argument "src\server.js" -WorkingDirectory $backend
Register-ScheduledTask -TaskName "NIDPS" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "[+] Task 'NIDPS' runs $node src\server.js in $backend at sign-in (elevated)." -ForegroundColor Green

if ($SnortInterface -ne "") {
    $snort = Join-Path $SnortDir "bin\snort.exe"
    $snortArgs = "-q -c `"$SnortDir\etc\nidps.conf`" -i $SnortInterface -l `"$SnortDir\log`""
    $snortAction = New-ScheduledTaskAction -Execute $snort -Argument $snortArgs
    Register-ScheduledTask -TaskName "NIDPS-Snort" -Action $snortAction -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "[+] Task 'NIDPS-Snort' runs Snort on adapter $SnortInterface at sign-in." -ForegroundColor Green
}
Write-Host "Start now without signing out: Start-ScheduledTask -TaskName NIDPS"
