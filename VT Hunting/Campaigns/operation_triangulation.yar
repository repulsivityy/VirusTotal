import "vt"

/*
Description: Hunting for indicators associated with Operation Triangulation
Author: dominicchua@google.com
https://securelist.com/trng-2023/
https://securelist.com/operation-triangulation/109842/ 
https://www.kaspersky.com/blog/triangulation-37c3-talk/50166/
*/

rule operationa_triangulation_cves {
meta:
  description = "Files weaponizing knwon opertaion_triangulation CVEs"
condition:
  for any tag in vt.metadata.tags : (
    tag == "cve-2023-32434" or
    tag == "cve-2023-32435" or
    tag == "cve-2023-41990" or 
    tag == "cve-2023-38606"
  )
}


rule known_c2_domains {
  meta:
    description = "Files contacting known Operation Triangulation C2 domains "
  condition:
      vt.metadata.itw.domain.raw endswith "addatamarket.net" or
      vt.metadata.itw.domain.raw endswith "backuprabbit.com" or
      vt.metadata.itw.domain.raw endswith "businessvideonews.com" or
      vt.metadata.itw.domain.raw endswith "cloudsponcer.com" or
      vt.metadata.itw.domain.raw endswith "datamarketplace.net" or
      vt.metadata.itw.domain.raw endswith "mobilegamerstats.com" or
      vt.metadata.itw.domain.raw endswith "snoweeanalytics.com" or
      vt.metadata.itw.domain.raw endswith "tagclick-cdn.com" or
      vt.metadata.itw.domain.raw endswith "topographyupdates.com" or
      vt.metadata.itw.domain.raw endswith "unlimitedteacup.com" or
      vt.metadata.itw.domain.raw endswith "virtuallaughing.com" or
      vt.metadata.itw.domain.raw endswith "web-trackers.com" or
      vt.metadata.itw.domain.raw endswith "growthtransport.com" or
      vt.metadata.itw.domain.raw endswith "anstv.net" or
      vt.metadata.itw.domain.raw endswith "ans7tv.net" and
      (
        vt.metadata.new_file
      )
}