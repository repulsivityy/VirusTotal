import "vt"

/*
Description: Rhysida hunting rules making use of Netloc
Author: dominicchua@google.com
https://www.hhs.gov/sites/default/files/rhysida-ransomware-sector-alert-tlpclear.pdf
https://research.checkpoint.com/2023/the-rhysida-ransomware-activity-analysis-and-ties-to-vice-society/
*/

rule Rhysida_PE_files {
meta:
  description = "searches based on known AV sig/engine detection"
//"entity:file engines:rhysida fs:2023-05-01+ p:1+ type:peexe" 
condition:
  for 1 engine, signature in vt.metadata.signatures: (  // At least 1 detection with engine called rhysida
    signature icontains "rhysida"
  ) and
  vt.metadata.analysis_stats.malicious >= 1 and  // To prevent FPs
  vt.metadata.file_type == vt.FileType.PE_EXE and 
  vt.metadata.first_submission_date > 2023-05-01
}


rule Rhysida_Non_PE_files {
meta:
  description = "non-pe files searches based on known AV sig/engine detection"
// "entity:file engines:rhysida fs:2023-05-01+ p:1+ NOT type:peexe"
condition:
  for 1 engine, signature in vt.metadata.signatures: (  // At least 1 detection with engine called rhysida
    signature icontains "rhysida"
  ) and
  vt.metadata.analysis_stats.malicious >= 1 and  // To prevent FPs
  vt.metadata.file_type != vt.FileType.PE_EXE and 
  vt.metadata.first_submission_date > 2023-05-01
}

rule Rhysida_behaviour {
meta:
  description = "detection based on behaviours like ransomnote, encrypted extensions, or known network infra"
// entity:file (behaviour_files:"*.rhysida" OR behaviour_files:"*CriticalBreachDetected.pdf") OR ((behaviour_network:"http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion/" OR behaviour_network:"onionmail.org")"
condition:
    // checks 1 - wallpaper or network infra
  for any vt_behaviour_command_executions in vt.behaviour.command_executions: (  //checks for wallpaper changeg
    vt_behaviour_command_executions icontains "/v Wallpaper /t REG_SZ /d \"%USERPROFILE%\\bg.jpg\" /f"
  ) or
  for any vt_behaviour_memory_pattern_urls in vt.behaviour.memory_pattern_urls: (
    vt_behaviour_memory_pattern_urls == "http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion/"
  ) or
  for any vt_behaviour_memory_pattern_domains in vt.behaviour.memory_pattern_domains: (
    vt_behaviour_memory_pattern_domains == "onionmail.org"
  ) and
  // checks 2 - behaviour
  for any vt_behaviour_files_written in vt.behaviour.files_written: (  //checks for ransomnote or encryption extension
    vt_behaviour_files_written icontains ".rhysida" or 
    vt_behaviour_files_written icontains "CriticalBreachDetected.pdf" 
  ) and
  // checks 3 - metadata
//  vt.metadata.analysis_stats.malicious >= 1 and 
  vt.metadata.file_type == vt.FileType.PE_EXE and 
  vt.metadata.first_submission_date > 2023-05-01 //not required for retrohunt
}