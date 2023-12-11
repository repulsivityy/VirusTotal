import "vt"

/*
Description: Hunting for CVE-2023-23397 .eml files making use of netloc
Author: dominicchua@google.com
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397
https://www.techtarget.com/searchsecurity/news/366562020/Fancy-Bear-hackers-still-exploiting-Microsoft-Exchange-flaw
https://thehackernews.com/2023/12/microsoft-warns-of-kremlin-backed-apt28.html
*/

rule cve_2023_23397_email_files {
meta:
  description = "Files weaponizing certain CVEs"
condition:
  for any tag in vt.metadata.tags : (
    tag == "cve-2023-23397"
  )
}


rule cve_2023_23397_engines {
  meta:
    description = "Files containing "
  condition:
    for any engine, signature in vt.metadata.signatures : (
    signature icontains "cve-2023-23397"
    )
}

