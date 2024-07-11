import "vt"
/*
Description: Eldorado Ransomware hunting based on Yara Netloc
Author: dominicchua@google.com
https://www.darkreading.com/endpoint-security/eldorado-ransomware-target-vmware-esxi
initial sample = "cb0b9e509a0f16eb864277cd76c4dcaa5016a356dd62c04dff8f8d96736174a7"
*/

rule eldorado_onion{
  condition:
    for any vt_behaviour_memory_pattern_domains in vt.behaviour.memory_pattern_domains: (
      vt_behaviour_memory_pattern_domains == "panelqbinglxczi2gqkwderfvgq6bcv5cbjwxrksjtvr5xv7ozh5wqad.onion"
    )
}

rule eldorado_behaviours {
  condition:
    for any cmd in vt.behaviour.command_executions: (
        cmd icontains "cmd \"/c chcp 65001 & systeminfo\"" //getting system info
    )  and
    for any vt_behaviour_files_dropped in vt.behaviour.files_dropped: (
        vt_behaviour_files_dropped.path == "HOW_RETURN_YOUR_DATA.TXT"
    )
}

rule eldorado_unq_cmd_exec {
    // capturing this due to unique command
  condition:
    for any unq_cmd_exec in vt.behaviour.processes_created: (
        unq_cmd_exec == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe powershell.exe -c \"$f='C:\\Users\\user\\Desktop\\trump.exe';while(Test-Path -Path $f){$o=new-object byte[] 10485760;(new-object Random).NextBytes($o);[IO.File]::WriteAllBytes($f,$o);Remove-Item -Path $f;Sleep 1;}\"" or
        unq_cmd_exec icontains "while(Test-Path -Path $f){$o=new-object byte[] 10485760;(new-object Random).NextBytes($o);[IO.File]::WriteAllBytes($f,$o);Remove-Item -Path $f;Sleep 1;}\""
    )
}
