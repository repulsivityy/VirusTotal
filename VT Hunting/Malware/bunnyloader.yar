import "vt"
/*
Description: BunnyLoader MaaS Hunting Rules making use of NetLoc
Author: dominicchua@google.com
https://www.zscaler.com/blogs/security-research/bunnyloader-newest-malware-service 
https://www.bleepingcomputer.com/news/security/new-bunnyloader-threat-emerges-as-a-feature-rich-malware-as-a-service/ 
*/

rule BunnyLoader_Mutex {
condition:
  for any mutex in vt.behaviour.mutexes_created : (
      mutex == "BunnyLoader_MUTEXCONTROL"
  )
}

rule BunnyLoader_Compression {
  condition:
    for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
      vt_behaviour_processes_created icontains "C:\\Windows\\system32\\cmd.exe /c powershell -Command Add-Type -A 'System.IO.Compression.FileSystem'; [System.IO.Compression.ZipFile]::CreateFromDirectory('C:\\Users\\<USER>\\AppData\\Local\\BunnyLogs'" or
      vt_behaviour_processes_created icontains "powershell -Command Add-Type -A 'System.IO.Compression.FileSystem'; [System.IO.Compression.ZipFile]::CreateFromDirectory('C:\\Users\\<USER>\\AppData\\Local\\BunnyLogs'"
    )
}

rule BunnyLoader_Exfil {
  condition:
    for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
      vt_behaviour_processes_created icontains "Bunny/Uploader.php"
    )
}

rule BunnyLoader_Regmods {
  condition:
    for any vt_behaviour_registry_keys_set in vt.behaviour.registry_keys_set: (
      vt_behaviour_registry_keys_set.key icontains "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Spyware_Blocker"
    )
}

rule BunnyLoader_Contact_Known_Infra {
  condition:
    for any vt_behaviour_http_conversations in vt.behaviour.http_conversations: (
      vt_behaviour_http_conversations.url icontains "Bunny/Heartbeat.php?" or 
      vt_behaviour_http_conversations.url icontains "Bunny/Add.php?" or
      vt_behaviour_http_conversations.url icontains "Bunny/Echoer.php?" or
      vt_behaviour_http_conversations.url icontains "Bunny/Uploader.php" 
    )
}
