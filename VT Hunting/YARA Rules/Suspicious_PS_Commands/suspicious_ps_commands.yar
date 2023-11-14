import "vt"
/*
Description: Suspicious Powershell Commands. Inspiration from Carbon Black days
Author: dominicchua@google.com
*/

rule suspicious_ps_cmds {
    strings: 
       // $s0 = "powershell"
        $s1 = "powershell.exe Set-ExecutionPolicy Bypass -enc"
        $s2 = "powershell.exe -NoProfile -ExecutionPolicy unrestricted"
        $s3 = "powershell.exe -w hidden -nop"
        $s4 = "powershell.exe -enc"
        $s5 = "IEX" nocase wide ascii
        $s6 = "new-object" nocase wide ascii
        $s7 = "invoke" nocase wide ascii
        $s8 = "-NoP" nocase wide ascii
        $s9 = "FromBase64String(" nocase wide ascii
        $10 = "[System.Convert]::" nocase wide ascii
    condition: 
        2 of them
}

rule suspicious_ps_cmds_yaranetloc {
    condition:
        for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
            vt_behaviour_processes_created icontains "powershell.exe Set-ExecutionPolicy Bypass -enc" or
            vt_behaviour_processes_created icontains "powershell.exe -NoProfile -ExecutionPolicy unrestricted" or
            vt_behaviour_processes_created icontains "powershell.exe -w hidden -nop" or 
            vt_behaviour_processes_created icontains "powershell.exe -enc" or 
            vt_behaviour_processes_created icontains "IEX" or
            vt_behaviour_processes_created icontains "new-object" or
            vt_behaviour_processes_created icontains "FromBase64String(" or 
            vt_behaviour_processes_created icontains "[System.Convert]::" or  
        )
}

rule suspicious_ps_downloads {
    strings: 
        $s1 = "powershell.exe IEX (New-Object Net.WebClient).DownloadString(http" nocase
    condition:
        any of them
}

rule suspicious_ps_regedit {
    strings: 
        $s1 = "powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run" nocase
    condition:
        any of them
}

rule suspicious_ps_regedit_netloc {
  condition:
    for any vt_behaviour_registry_keys_opened in vt.behaviour.registry_keys_opened: (
      vt_behaviour_registry_keys_opened == "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
}