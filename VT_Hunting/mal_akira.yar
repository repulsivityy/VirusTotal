rule Akira_Behaviour {
meta:
  description = "New Akira Files"
  author = "dominicchua@"
  samples = "89f5f29cf6b5bcfc85b506fb916da66cb7fd398cf6011d58e9409c7813e1a6f3, d8903520a4635595e78c4815dbf2937e766edbc1f8dd7d32e2309acdfbbf598b"
condition:
    for 3 engine, signature in vt.metadata.signatures: (  // At least 3 ransom detections
        signature icontains "akira"
    ) and
    for any file_mod in vt.behaviour.files_opened: (  // creation of ransom note
      file_mod icontains "akira_readme.txt" or
      file_mod icontains ".akira"
    ) and
    for any mem_pattern in vt.behaviour.memory_pattern_urls: ( // check akira onion site
        mem_pattern icontains "//akira" and 
        mem_pattern icontains ".onion"
    ) and
    for any proc_mod in vt.behaviour.processes_created: ( // specific akira behaviour
    proc_mod icontains "powershell.exe -Command \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\""
    ) and 
    (// To prevent FPs
        vt.metadata.analysis_stats.malicious >= 5 
        or   
        vt.metadata.gti_assessment.threat_score.value >= 60
    ) and
    vt.metadata.new_file // new file to GTI
}