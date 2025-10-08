# A list of API calls from IOC Stream for URLs
A list of API calls to the IOC_Stream API Endpoint for AI / LLMs to fully understand the different filters and results of the API calls. 

## Example 1: No filters with descriptors_only=false and entity:url
>limited to 1 object for brevity

### Sample Request with descriptors_only=false and entity:url
```
curl --request GET \
     --url 'https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false&filter=entity_type%3Aurl' \
     --header 'accept: application/json' \
     --header 'x-apikey: <api-key>'
```

### Sample Request with descriptors_only=false and entity:url
```
{
  "data": [
    {
      "id": "c29d620a19de6664bc458c4fa698bd7b6c7193a602a6b236171c4893fd41ee50",
      "type": "url",
      "links": {
        "self": "https://www.virustotal.com/api/v3/urls/c29d620a19de6664bc458c4fa698bd7b6c7193a602a6b236171c4893fd41ee50"
      },
      "attributes": {
        "last_modification_date": 1759888968,
        "outgoing_links": [
          "https://www.linkedin.com/company/chase?trk=company_logo",
          "https://creditcards.chase.com/business-credit-cards?CELL=6HK5",
          "https://optout.aboutads.info/?c=2&lang=EN",
          "https://instagram.com/chase",
          "https://www.jpmorgan.com/commercial-banking",
          "https://www.jpmorgan.com/europe/merchant-services",
          "https://www.chase.com/",
          "https://twitter.com/Chase",
          "https://locator.chase.com/",
          "https://www.youtube.com/chase",
          "https://play.google.com/store/apps/details?id=com.chase.smb.chasepaymentsolutions&hl=en_US&gl=US",
          "https://creditcards.chase.com/business-credit-cards",
          "https://media.chase.com",
          "https://careers.jpmorgan.com/US/en/chase",
          "https://merchantservices.chase.ca/fr",
          "https://merchantservices.chase.ca/en",
          "https://developer.apple.com/tap-to-pay/regions/",
          "https://www.facebook.com/chase",
          "https://survey.experience.chase.com/jfe/form/SV_0rBuvmGXX6OhYEJ",
          "https://www.pinterest.com/chase/",
          "https://apps.apple.com/us/app/chase-point-of-sale-pos/id6443472426",
          "https://www.jpmorganchase.com",
          "https://www.chase.com/personal/offers/secureshopping?CELL=6TKV",
          "https://www.jpmorgan.com/global",
          "https://merchantservices.chase.com/support",
          "https://www.jpmorgan.com/global/cib/investment-banking",
          "https://am.jpmorgan.com/us/asset-management/welcome/"
        ],
        "last_http_response_code": 200,
        "categories": {
          "BitDefender": "business",
          "Sophos": "information technology",
          "Forcepoint ThreatSeeker": "financial data and services",
          "Xcitium Verdict Cloud": "finance & investment"
        },
        "has_content": false,
        "last_analysis_date": 1759888655,
        "last_analysis_stats": {
          "malicious": 0,
          "suspicious": 0,
          "undetected": 31,
          "harmless": 67,
          "timeout": 0
        },
        "last_http_response_content_length": 487208,
        "last_http_response_content_sha256": "b246473bbbc44c6debc503d3a0e50ef0962a4448c12a950d65055b6cdb214aa0",
        "total_votes": {
          "harmless": 0,
          "malicious": 0
        },
        "last_http_response_cookies": {
          "AKA_A2": "A"
        },
        "trackers": {
          "Google Tag Manager": [
            {
              "url": "https://www.googletagmanager.com/gtag/js?id=DC-2348473",
              "id": "DC-2348473",
              "timestamp": 1759880311
            }
          ],
          "Adobe Dynamic Tag Management": [
            {
              "url": "https://assets.adobedtm.com/b968b9f97b30/5c4659e4aaa9/launch-ENc5955f7e97b54b51907c0a8db6686a4f.min.js",
              "id": "b968b9f97b30",
              "timestamp": 1726272622
            },
            {
              "url": "//assets.adobedtm.com/launch-EN6616d492cc1f43698457ac5bbaf8f2fb.min.js",
              "timestamp": 1642148331,
              "id": "launch-EN6616d492cc1f43698457ac5bbaf8f2fb.min.j"
            }
          ]
        },
        "url": "https://opt.chasepaymentech.com/",
        "last_submission_date": 1759888655,
        "redirection_chain": [
          "https://opt.chasepaymentech.com/",
          "http://www.chasepaymentech.com/",
          "https://www.chasepaymentech.com/",
          "https://merchantservices.chase.com"
        ],
        "last_http_response_headers": {
          "Content-Type": "text/html; charset=utf-8",
          "x-dispatcher": "dispatcher2useast1-29291975",
          "Accept-CH": "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Model, Sec-CH-UA-Bitness, Sec-CH-UA-Wow64",
          "Permissions-Policy": "ch-ua-full-version-list=(\"https://*.chase.com\"),ch-ua-platform-version=(\"https://*.chase.com\"),ch-ua-arch=(\"https://*.chase.com\"),ch-ua-model=(\"https://*.chase.com\"),ch-ua-bitness=(\"https://*.chase.com\"),ch-ua-wow64=(\"https://*.chase.com\")",
          "ETag": "\"ws2rdy8wsfabsv\"",
          "Vary": "Accept-Encoding",
          "Access-Control-Allow-Origin": "*",
          "x-xss-protection": "1; mode=block",
          "X-Frame-Options": "SAMEORIGIN",
          "X-Content-Security-Policy": "frame-ancestors 'none'",
          "Content-Security-Policy": "frame-ancestors 'none'",
          "X-Content-Type-Options": "nosniff",
          "x-b3-traceid": "86cc46e9b36e1f021e60281ad56befaa",
          "X-Akamai-Transformed": "9l - 0 pmb=mRUM,2",
          "Cache-Control": "public, max-age=311",
          "Date": "Wed, 08 Oct 2025 01:57:39 GMT",
          "Transfer-Encoding": "chunked",
          "Connection": "keep-alive, Transfer-Encoding",
          "Set-Cookie": "AKA_A2=A; expires=Wed, 08-Oct-2025 02:57:39 GMT; path=/; domain=chase.com; secure; HttpOnly",
          "Link": "<https://asset.chase.com/content/dam/cpo-static/fonts/opensans-extrabold.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://asset.chase.com/content/dam/cpo-static/fonts/opensans-italic.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://asset.chase.com/content/dam/cpo-static/fonts/opensans-extrabold-italic.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://asset.chase.com/content/dam/cpo-static/fonts/opensans-light-italic.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://asset.chase.com/content/dam/cpo-static/fonts/opensans-semibold-italic.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://asset.chase.com/content/dam/cpo-static/fonts/opensans-bold-italic.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://www.chase.com/_next/static/media/mds-chase-icons.8f438e32.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin, <https://asset.chase.com/content/dam/cpo-static/fonts/opensans.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://asset.chase.com/content/dam/cpo-static/fonts/opensans-bold.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://asset.chase.com/content/dam/cpo-static/fonts/opensans-semibold.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin,<https://asset.chase.com/content/dam/cpo-static/fonts/opensans-light.woff2>;rel=\"preload\";as=\"font\";type=\"font/woff2\";crossorigin, <https://p11.techlab-cdn.com>;rel=\"preconnect\",<https://munchkin.marketo.net>;rel=\"preconnect\",<https://vjs.zencdn.net>;rel=\"preconnect\", <https://asset.chase.com>;rel=\"preconnect\"",
          "Strict-Transport-Security": "max-age=31536000",
          "x-amzn-trace-id": "0.4f18d017.1759888659.d417e7b9",
          "Server-Timing": "cdn-cache; desc=REVALIDATE, edge; dur=24, origin; dur=19, ak_p; desc=\"1759888659415_399513679_3558336441_4356_8500_9_18_-\";dur=1"
        },
        "favicon": {
          "raw_md5": "3d7d2ca3139afc301b9ac063b58e6d95",
          "dhash": "71d296070796b4f1"
        },
        "last_analysis_results": {
          "Artists Against 419": {
            "method": "blacklist",
            "engine_name": "Artists Against 419",
            "category": "harmless",
            "result": "clean"
          },
          "Acronis": {
            "method": "blacklist",
            "engine_name": "Acronis",
            "category": "harmless",
            "result": "clean"
          },
          "Abusix": {
            "method": "blacklist",
            "engine_name": "Abusix",
            "category": "harmless",
            "result": "clean"
          },
          "ADMINUSLabs": {
            "method": "blacklist",
            "engine_name": "ADMINUSLabs",
            "category": "harmless",
            "result": "clean"
          },
          "Lionic": {
            "method": "blacklist",
            "engine_name": "Lionic",
            "category": "harmless",
            "result": "clean"
          },
          "Criminal IP": {
            "method": "blacklist",
            "engine_name": "Criminal IP",
            "category": "harmless",
            "result": "clean"
          },
          "AILabs (MONITORAPP)": {
            "method": "blacklist",
            "engine_name": "AILabs (MONITORAPP)",
            "category": "harmless",
            "result": "clean"
          },
          "AlienVault": {
            "method": "blacklist",
            "engine_name": "AlienVault",
            "category": "harmless",
            "result": "clean"
          },
          "alphaMountain.ai": {
            "method": "blacklist",
            "engine_name": "alphaMountain.ai",
            "category": "undetected",
            "result": "unrated"
          },
          "AlphaSOC": {
            "method": "blacklist",
            "engine_name": "AlphaSOC",
            "category": "undetected",
            "result": "unrated"
          },
          "Antiy-AVL": {
            "method": "blacklist",
            "engine_name": "Antiy-AVL",
            "category": "harmless",
            "result": "clean"
          },
          "ArcSight Threat Intelligence": {
            "method": "blacklist",
            "engine_name": "ArcSight Threat Intelligence",
            "category": "undetected",
            "result": "unrated"
          },
          "AutoShun": {
            "method": "blacklist",
            "engine_name": "AutoShun",
            "category": "undetected",
            "result": "unrated"
          },
          "Axur": {
            "method": "blacklist",
            "engine_name": "Axur",
            "category": "undetected",
            "result": "unrated"
          },
          "benkow.cc": {
            "method": "blacklist",
            "engine_name": "benkow.cc",
            "category": "harmless",
            "result": "clean"
          },
          "Bfore.Ai PreCrime": {
            "method": "blacklist",
            "engine_name": "Bfore.Ai PreCrime",
            "category": "undetected",
            "result": "unrated"
          },
          "BitDefender": {
            "method": "blacklist",
            "engine_name": "BitDefender",
            "category": "harmless",
            "result": "clean"
          },
          "Bkav": {
            "method": "blacklist",
            "engine_name": "Bkav",
            "category": "undetected",
            "result": "unrated"
          },
          "BlockList": {
            "method": "blacklist",
            "engine_name": "BlockList",
            "category": "harmless",
            "result": "clean"
          },
          "Blueliv": {
            "method": "blacklist",
            "engine_name": "Blueliv",
            "category": "harmless",
            "result": "clean"
          },
          "Certego": {
            "method": "blacklist",
            "engine_name": "Certego",
            "category": "harmless",
            "result": "clean"
          },
          "ChainPatrol": {
            "method": "blacklist",
            "engine_name": "ChainPatrol",
            "category": "undetected",
            "result": "unrated"
          },
          "Chong Lua Dao": {
            "method": "blacklist",
            "engine_name": "Chong Lua Dao",
            "category": "harmless",
            "result": "clean"
          },
          "CINS Army": {
            "method": "blacklist",
            "engine_name": "CINS Army",
            "category": "harmless",
            "result": "clean"
          },
          "Snort IP sample list": {
            "method": "blacklist",
            "engine_name": "Snort IP sample list",
            "category": "harmless",
            "result": "clean"
          },
          "Cluster25": {
            "method": "blacklist",
            "engine_name": "Cluster25",
            "category": "undetected",
            "result": "unrated"
          },
          "CMC Threat Intelligence": {
            "method": "blacklist",
            "engine_name": "CMC Threat Intelligence",
            "category": "harmless",
            "result": "clean"
          },
          "Xcitium Verdict Cloud": {
            "method": "blacklist",
            "engine_name": "Xcitium Verdict Cloud",
            "category": "undetected",
            "result": "unrated"
          },
          "CRDF": {
            "method": "blacklist",
            "engine_name": "CRDF",
            "category": "harmless",
            "result": "clean"
          },
          "CSIS Security Group": {
            "method": "blacklist",
            "engine_name": "CSIS Security Group",
            "category": "undetected",
            "result": "unrated"
          },
          "Cyan": {
            "method": "blacklist",
            "engine_name": "Cyan",
            "category": "undetected",
            "result": "unrated"
          },
          "Cyble": {
            "method": "blacklist",
            "engine_name": "Cyble",
            "category": "harmless",
            "result": "clean"
          },
          "CyRadar": {
            "method": "blacklist",
            "engine_name": "CyRadar",
            "category": "harmless",
            "result": "clean"
          },
          "desenmascara.me": {
            "method": "blacklist",
            "engine_name": "desenmascara.me",
            "category": "harmless",
            "result": "clean"
          },
          "DNS8": {
            "method": "blacklist",
            "engine_name": "DNS8",
            "category": "harmless",
            "result": "clean"
          },
          "Dr.Web": {
            "method": "blacklist",
            "engine_name": "Dr.Web",
            "category": "harmless",
            "result": "clean"
          },
          "Emsisoft": {
            "method": "blacklist",
            "engine_name": "Emsisoft",
            "category": "harmless",
            "result": "clean"
          },
          "Ermes": {
            "method": "blacklist",
            "engine_name": "Ermes",
            "category": "undetected",
            "result": "unrated"
          },
          "ESET": {
            "method": "blacklist",
            "engine_name": "ESET",
            "category": "harmless",
            "result": "clean"
          },
          "ESTsecurity": {
            "method": "blacklist",
            "engine_name": "ESTsecurity",
            "category": "harmless",
            "result": "clean"
          },
          "EmergingThreats": {
            "method": "blacklist",
            "engine_name": "EmergingThreats",
            "category": "harmless",
            "result": "clean"
          },
          "Feodo Tracker": {
            "method": "blacklist",
            "engine_name": "Feodo Tracker",
            "category": "harmless",
            "result": "clean"
          },
          "Fortinet": {
            "method": "blacklist",
            "engine_name": "Fortinet",
            "category": "harmless",
            "result": "clean"
          },
          "G-Data": {
            "method": "blacklist",
            "engine_name": "G-Data",
            "category": "harmless",
            "result": "clean"
          },
          "Google Safebrowsing": {
            "method": "blacklist",
            "engine_name": "Google Safebrowsing",
            "category": "harmless",
            "result": "clean"
          },
          "GCP Abuse Intelligence": {
            "method": "blacklist",
            "engine_name": "GCP Abuse Intelligence",
            "category": "undetected",
            "result": "unrated"
          },
          "GreenSnow": {
            "method": "blacklist",
            "engine_name": "GreenSnow",
            "category": "harmless",
            "result": "clean"
          },
          "Gridinsoft": {
            "method": "blacklist",
            "engine_name": "Gridinsoft",
            "category": "undetected",
            "result": "unrated"
          },
          "Heimdal Security": {
            "method": "blacklist",
            "engine_name": "Heimdal Security",
            "category": "harmless",
            "result": "clean"
          },
          "Hunt.io Intelligence": {
            "method": "blacklist",
            "engine_name": "Hunt.io Intelligence",
            "category": "undetected",
            "result": "unrated"
          },
          "IPsum": {
            "method": "blacklist",
            "engine_name": "IPsum",
            "category": "harmless",
            "result": "clean"
          },
          "Juniper Networks": {
            "method": "blacklist",
            "engine_name": "Juniper Networks",
            "category": "harmless",
            "result": "clean"
          },
          "Kaspersky": {
            "method": "blacklist",
            "engine_name": "Kaspersky",
            "category": "harmless",
            "result": "clean"
          },
          "Lumu": {
            "method": "blacklist",
            "engine_name": "Lumu",
            "category": "undetected",
            "result": "unrated"
          },
          "Malwared": {
            "method": "blacklist",
            "engine_name": "Malwared",
            "category": "harmless",
            "result": "clean"
          },
          "MalwareURL": {
            "method": "blacklist",
            "engine_name": "MalwareURL",
            "category": "undetected",
            "result": "unrated"
          },
          "MalwarePatrol": {
            "method": "blacklist",
            "engine_name": "MalwarePatrol",
            "category": "harmless",
            "result": "clean"
          },
          "malwares.com URL checker": {
            "method": "blacklist",
            "engine_name": "malwares.com URL checker",
            "category": "harmless",
            "result": "clean"
          },
          "Mimecast": {
            "method": "blacklist",
            "engine_name": "Mimecast",
            "category": "undetected",
            "result": "unrated"
          },
          "Netcraft": {
            "method": "blacklist",
            "engine_name": "Netcraft",
            "category": "undetected",
            "result": "unrated"
          },
          "OpenPhish": {
            "method": "blacklist",
            "engine_name": "OpenPhish",
            "category": "harmless",
            "result": "clean"
          },
          "0xSI_f33d": {
            "method": "blacklist",
            "engine_name": "0xSI_f33d",
            "category": "undetected",
            "result": "unrated"
          },
          "Phishing Database": {
            "method": "blacklist",
            "engine_name": "Phishing Database",
            "category": "harmless",
            "result": "clean"
          },
          "PhishFort": {
            "method": "blacklist",
            "engine_name": "PhishFort",
            "category": "undetected",
            "result": "unrated"
          },
          "PhishLabs": {
            "method": "blacklist",
            "engine_name": "PhishLabs",
            "category": "undetected",
            "result": "unrated"
          },
          "Phishtank": {
            "method": "blacklist",
            "engine_name": "Phishtank",
            "category": "harmless",
            "result": "clean"
          },
          "PREBYTES": {
            "method": "blacklist",
            "engine_name": "PREBYTES",
            "category": "harmless",
            "result": "clean"
          },
          "PrecisionSec": {
            "method": "blacklist",
            "engine_name": "PrecisionSec",
            "category": "undetected",
            "result": "unrated"
          },
          "Quick Heal": {
            "method": "blacklist",
            "engine_name": "Quick Heal",
            "category": "harmless",
            "result": "clean"
          },
          "Quttera": {
            "method": "blacklist",
            "engine_name": "Quttera",
            "category": "harmless",
            "result": "clean"
          },
          "Rising": {
            "method": "blacklist",
            "engine_name": "Rising",
            "category": "harmless",
            "result": "clean"
          },
          "SafeToOpen": {
            "method": "blacklist",
            "engine_name": "SafeToOpen",
            "category": "undetected",
            "result": "unrated"
          },
          "Sangfor": {
            "method": "blacklist",
            "engine_name": "Sangfor",
            "category": "harmless",
            "result": "clean"
          },
          "Sansec eComscan": {
            "method": "blacklist",
            "engine_name": "Sansec eComscan",
            "category": "undetected",
            "result": "unrated"
          },
          "Scantitan": {
            "method": "blacklist",
            "engine_name": "Scantitan",
            "category": "harmless",
            "result": "clean"
          },
          "SCUMWARE.org": {
            "method": "blacklist",
            "engine_name": "SCUMWARE.org",
            "category": "harmless",
            "result": "clean"
          },
          "Seclookup": {
            "method": "blacklist",
            "engine_name": "Seclookup",
            "category": "harmless",
            "result": "clean"
          },
          "SOCRadar": {
            "method": "blacklist",
            "engine_name": "SOCRadar",
            "category": "undetected",
            "result": "unrated"
          },
          "Sophos": {
            "method": "blacklist",
            "engine_name": "Sophos",
            "category": "harmless",
            "result": "clean"
          },
          "Spam404": {
            "method": "blacklist",
            "engine_name": "Spam404",
            "category": "harmless",
            "result": "clean"
          },
          "StopForumSpam": {
            "method": "blacklist",
            "engine_name": "StopForumSpam",
            "category": "harmless",
            "result": "clean"
          },
          "Sucuri SiteCheck": {
            "method": "blacklist",
            "engine_name": "Sucuri SiteCheck",
            "category": "harmless",
            "result": "clean"
          },
          "securolytics": {
            "method": "blacklist",
            "engine_name": "securolytics",
            "category": "harmless",
            "result": "clean"
          },
          "Threatsourcing": {
            "method": "blacklist",
            "engine_name": "Threatsourcing",
            "category": "harmless",
            "result": "clean"
          },
          "ThreatHive": {
            "method": "blacklist",
            "engine_name": "ThreatHive",
            "category": "harmless",
            "result": "clean"
          },
          "Trustwave": {
            "method": "blacklist",
            "engine_name": "Trustwave",
            "category": "harmless",
            "result": "clean"
          },
          "Underworld": {
            "method": "blacklist",
            "engine_name": "Underworld",
            "category": "undetected",
            "result": "unrated"
          },
          "URLhaus": {
            "method": "blacklist",
            "engine_name": "URLhaus",
            "category": "harmless",
            "result": "clean"
          },
          "URLQuery": {
            "method": "blacklist",
            "engine_name": "URLQuery",
            "category": "undetected",
            "result": "unrated"
          },
          "Viettel Threat Intelligence": {
            "method": "blacklist",
            "engine_name": "Viettel Threat Intelligence",
            "category": "harmless",
            "result": "clean"
          },
          "VIPRE": {
            "method": "blacklist",
            "engine_name": "VIPRE",
            "category": "undetected",
            "result": "unrated"
          },
          "ViriBack": {
            "method": "blacklist",
            "engine_name": "ViriBack",
            "category": "harmless",
            "result": "clean"
          },
          "VX Vault": {
            "method": "blacklist",
            "engine_name": "VX Vault",
            "category": "harmless",
            "result": "clean"
          },
          "Webroot": {
            "method": "blacklist",
            "engine_name": "Webroot",
            "category": "harmless",
            "result": "clean"
          },
          "Forcepoint ThreatSeeker": {
            "method": "blacklist",
            "engine_name": "Forcepoint ThreatSeeker",
            "category": "harmless",
            "result": "clean"
          },
          "Yandex Safebrowsing": {
            "method": "blacklist",
            "engine_name": "Yandex Safebrowsing",
            "category": "harmless",
            "result": "clean"
          },
          "ZeroCERT": {
            "method": "blacklist",
            "engine_name": "ZeroCERT",
            "category": "harmless",
            "result": "clean"
          },
          "ZeroFox": {
            "method": "blacklist",
            "engine_name": "ZeroFox",
            "category": "undetected",
            "result": "unrated"
          }
        },
        "reputation": 0,
        "threat_severity": {
          "version": "U3",
          "threat_severity_level": "SEVERITY_NONE",
          "threat_severity_data": {},
          "last_analysis_date": "1759888967",
          "level_description": "No severity score data"
        },
        "times_submitted": 2425,
        "first_submission_date": 1568366016,
        "tld": "com",
        "threat_names": [],
        "last_final_url": "http://www.chasepaymentech.com/",
        "html_meta": {
          "description": [
            "Merchant services from Chase offer comprehensive solutions for businesses, including payment processing, point-of-sale systems and online payment gateways."
          ],
          "viewport": [
            "width=device-width, initial-scale=1.0"
          ],
          "msapplication-TileColor": [
            "#FFFFFF"
          ],
          "msapplication-TileImage": [
            "/etc/designs/chase-ux/favicon-144.png"
          ],
          "apple-itunes-app": [
            "app-id=298867247, affiliate-data=JPMorganChase"
          ],
          "next-head-count": [
            "19"
          ]
        },
        "tags": [
          "external-resources",
          "iframes",
          "third-party-cookies"
        ]
      },
      "context_attributes": {
        "notification_id": "23413611042",
        "origin": "hunting",
        "notification_date": 1759895871,
        "sources": [
          {
            "id": "17635806915",
            "type": "hunting_ruleset",
            "label": "JumpStart_Phishing_Favicon"
          }
        ],
        "tags": [
          "jumpstart_phishing_favicon",
          "urlswithmyfavicon"
        ],
        "hunting_info": {
          "rule_name": "urlsWithMyFavIcon",
          "match_source": "URL_RESPONSE_BODY",
          "source_key": "9a4b8f62",
          "source_country": "US"
        }
      }
    }
  ],
  "meta": {
    "cursor": "eJwNy11vgyAUANC_5Edd9jpTce1yYSh4wTdbu7ZwNTTZgiP78evjeTh_o6GPmcI3rmFCxoIqQn3O6EeudIc8RPQzXjQ9TgX1nT_qHqmcEH6FIS8zXwxlYJBVekrd58B0ptbAnv_RmyC6ZnhRS2CXJm-0oeNp31Rf71sB5fYK6pwLda14ggzM08gctDaOqHe8lTuB_M73jGyqCdLseLp564hgaaJ1nbOuvoE75NbNbkS5cYQKChutukbRytIusPG3f49yTCM=",
    "count": 1572
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false&filter=entity_type:url",
    "next": "https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false&filter=entity_type%3Aurl&cursor=eJwNy11vgyAUANC_5Edd9jpTce1yYSh4wTdbu7ZwNTTZgiP78evjeTh_o6GPmcI3rmFCxoIqQn3O6EeudIc8RPQzXjQ9TgX1nT_qHqmcEH6FIS8zXwxlYJBVekrd58B0ptbAnv_RmyC6ZnhRS2CXJm-0oeNp31Rf71sB5fYK6pwLda14ggzM08gctDaOqHe8lTuB_M73jGyqCdLseLp564hgaaJ1nbOuvoE75NbNbkS5cYQKChutukbRytIusPG3f49yTCM%3D"
  }
}
```