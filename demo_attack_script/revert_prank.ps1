# 1. Delete the Scheduled Task
# The -ErrorAction SilentlyContinue prevents errors if the task was already deleted.
Write-Host "Removing the scheduled task..." -ForegroundColor Cyan
schtasks /delete /tn "USB_Hardware_Prank" /f 2>$null

# 2. Stop any running instances of the prank script
# We look for PowerShell processes that have the script name in their command line.
Write-Host "Stopping any active prank scripts..." -ForegroundColor Cyan
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' AND CommandLine LIKE '%prank.ps1%'" | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force
    Write-Host "Stopped process ID: $($_.ProcessId)" -ForegroundColor Yellow
}

# 3. Optional: Clean up the desktop shortcuts created by the prank
$ShortcutPath = "$Home\Desktop\USB Hardware*.lnk"
if (Test-Path $ShortcutPath) {
    Write-Host "Cleaning up desktop shortcuts..." -ForegroundColor Cyan
    Remove-Item $ShortcutPath
}

Write-Host "System reverted safely." -ForegroundColor Green

# 4. Critial - Delete lightpipe.exe malware // Update this based on the payload in download_and_run.ps1

$ScriptDir = "$env:TEMP"
$FilePath = "$ScriptDir\lightpipe.exe"

Remove-Item -Path "$FilePath" -Force -ErrorAction SilentlyContinue