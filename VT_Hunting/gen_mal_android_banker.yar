import "vt"

rule GEN_MAL_Android_Banker {
  meta:
    target_entity = "apk file"
    description = "searches for malicious APK files tagged as banker/trojan newly submitted to VT/GTI, observed in ID/SEA"
    date = "16-Sep-2026"
    last_modified = "16-Sep-2026"
    classification = "TLP:CLEAR"
    version = "1.0"
    search_term = "entity:file AND type:apk AND (engine:trojan OR engine:banker) AND (gti_score:30+ OR gti_verdict:malicious OR p:5+) AND submitter:ID"

  condition:
    ( // at least 2 3P vendors detected it as a trojan or banker
        (
            for 2 engine, signature in vt.metadata.signatures: (  
            signature icontains "trojan"
            )
        or 
            for 2 engine, signature in vt.metadata.signatures: (  
            signature icontains "banker"
            )
        )
    )
    and 
    ( // provides basic filters to reduce noise
        vt.metadata.gti_assessment.verdict.value == vt.GtiVerdict.VERDICT_MALICIOUS // GTI_VERDICT=MALICIOUS
        or 
        vt.metadata.gti_assessment.threat_score.value >= 30 // GTI_Score >= 30
        or
        vt.metadata.analysis_stats.malicious >= 5 // >=5 3P security vendors detecting it as malicious
    )
    and
    vt.metadata.file_type == vt.FileType.ANDROID // Android File
    and
    vt.metadata.new_file // New IOC to GTI
    and
    vt.metadata.submitter.country == "ID" // Sample was submitted from ID
    
    //( // Covers major countries in SEA
    //    vt.metadata.submitter.country == "ID" or
    //    vt.metadata.submitter.country == "SG" or
    //    vt.metadata.submitter.country == "MY" or
    //    vt.metadata.submitter.country == "TH" or
    //    vt.metadata.submitter.country == "VN"
    //)
}
