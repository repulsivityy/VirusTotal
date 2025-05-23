import "vt"

rule BERT_Ransomware {
meta:
  description = "New BERT Files"
  author = "dominicchua@"
  ref = "https://www.pcrisk.com/removal-guides/32835-bert-ransomware, https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/bert"
  ref2 = "https://www.ransomware.live/ransomnote/bert/note.txt"
strings:
    $s1 = "Hello from Bert!"
    $s2 = "Download the (Session) messenger (https://getsession.org)"
condition:
    for any file_mod in vt.behaviour.files_written: (  // creation of ransom note
      file_mod icontains ".encryptedbybert"
    ) 
    or
    for any mem_pattern in vt.behaviour.memory_pattern_urls: ( // check akira onion site
        mem_pattern icontains "//bert" and 
        mem_pattern icontains ".onion"
    ) and
    vt.metadata.new_file // new file to GTI
    and 
    1 of ($s*)
}
