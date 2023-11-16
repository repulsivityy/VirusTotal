import "vt"

/*
Description: Royal Ransomware hunting rules making use of Netloc
Author: dominicchua@google.com
https://www.cisa.gov/sites/default/files/2023-11/aa23-061a-stopransomware-royal-ransomware-update.pdf
https://www.cybereason.com/blog/royal-ransomware-analysis
*/

rule royal_ransomware_behaviour {
    meta: 
        description = "detections based on known behaviours such as ransom note, encrypted extensions, or known network infra"
    strings: 
        $x_ext1 = ".royal" wide
        $x_ext2 = ".royal_" wide
        $r_note = "README.TXT" nocase wide  //ransom note
        $r_site = "royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion" //embedded onion site"
    condition: 
        (
            for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
            vt_behaviour_processes_created == "delete shadows /all /quiet" //behaviour on windows
            ) or 
            for any vt_behaviour_command_executions in vt.behaviour.command_executions: (
            vt_behaviour_command_executions icontains "apparmor_parser"     //behaviour on linux
            ) 
        ) and
        (
            (1 of ($x*)) and    //matches one of the extensions
            (1 of ($r*))        //matches one of the behaviour
        ) 
        and
        (
            vt.metadata.file_type == vt.FileType.PE_EXE or 
            vt.metadata.file_type == vt.FileType.ELF
        ) and 
        vt.metadata.new_file // to search for new files
}
