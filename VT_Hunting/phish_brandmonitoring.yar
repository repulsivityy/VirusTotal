import "vt"

rule brand_monitoring_livehuntrule {
meta:
    description = "Potential phishing against Google"
    author = "dominicchua@"
    target_entity = "url"

condition: 
    (
        // condition 1: favicon reuse
        vt.net.url.favicon.dhash == "f0cc929ab296cc71" or 

        (
        // condition 2: html title. 
            vt.net.url.html_title icontains "Google" or
            vt.net.url.html_title icontains "Gmail"
        ) or 
        
        // condition 3: SSL cert CN 
        vt.net.domain.https_certificate.subject.common_name == "www.google.com" 
        or
        
        //(   
            // condition 4: fuzzy search - need to check as it might be for domains only
            //vt.net.domain.permutation_of("google.com", vt.net.url.hostname.TYPO | vt.net.domain.HOMOGLYPH | vt.net.domain.HYPHENATION | vt.net.domain.BITSQUATTING | vt.net.domain.SUBDOMAIN)
        //) or
        
        (
            // raw url contains domain name
            vt.net.url.raw icontains "google" 
        ) 
    ) 
    and 
    ( // filters out legit domains
        vt.net.domain.root != "google.com" or 
        not vt.net.url.raw istartswith "https://www.google.com/"
    ) 
    and 
    ( // thresholds to prevent noise
        for any engine, signature in vt.net.url.signatures : (
            signature icontains "phishing"
        ) or 
        vt.net.url.gti_assessment.threat_score.value >= 10
        or 
        vt.net.url.analysis_stats.malicious >=5 

    )
    and 
    vt.net.url.new_url // for new urls to GTI 
}
