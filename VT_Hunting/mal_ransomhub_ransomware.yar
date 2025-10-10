import "vt"

rule GTI_Snippets_Ransomhub {
meta:
  description = "New files detected as ransomware"
  author = "dominicchua@"
  hashes = "34e479181419efd0c00266bef0210f267beaa92116e18f33854ca420f65e2087, 104b22a45e4166a5473c9db924394e1fe681ef374970ed112edd089c4c8b83f2" //behaviour 
  search_term = "entity:file engines:ransomhub gti_score:80+ submitter:us submissions:50+" // got gti snippets
strings:
    $a1 = "white_files" ascii fullword
    $a2 = "note_file_name" ascii fullword
    $a3 = "note_short_text" ascii fullword
    $a4 = "set_wallpaper" ascii fullword
    $a5 = "local_disks" ascii fullword
    $a6 = "running_one" ascii fullword
    $a7 = "net_spread" ascii fullword
    $a8 = "kill_processes" ascii fullword
    $a9 = "stolen and encrypted" ascii fullword
condition:
    ( //behaviour based on hashes
        (
            for any proc_injection in vt.behaviour.processes_injected: (
                proc_injection icontains "%SAMPLEPATH%\\sjaw.exe"
            ) or
            for any cmd_exec in vt.behaviour.command_executions: (
                cmd_exec icontains "\"%SAMPLEPATH%\\sjaw.exe\" "
            ) 
            and
            for any del_shadows in vt.behaviour.command_executions: (
                del_shadows icontains "vssadmin  Delete Shadows /All /Quiet" or //using vss
                del_shadows icontains "cmd /c wmic SHADOWCOPY /nointeractive" //using wmic
            ) 
        ) 
        or
        for any mem_pattern in vt.behaviour.memory_pattern_urls: (
            mem_pattern icontains "http://knight" and
            mem_pattern icontains ".onion"
        )
        or
        ( //based on search terms
            for 2 engine, signature in vt.metadata.signatures: (  
            signature icontains "ransomhub"
            ) and
            vt.metadata.gti_assessment.threat_score.value >= 80 
            //and
            //vt.metadata.submitter.country == "US" 
            //and
            //vt.metadata.times_submitted >= 50
            //and
            //vt.metadata.new_file
        )
        and
        for 3 win_api in vt.behaviour.calls_highlighted: (
            win_api == "GetAdaptersAddresses" or 
            win_api == "ShellExecuteW" or 
            win_api == "CreateFileW" or 
            win_api == "WriteFile" or
            win_api == "ShellExecuteW"
        ) 
    ) 
    and
    5 of ($a*) // including strings
}