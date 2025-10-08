# A list of API calls from IOC Stream for IP Address only
A list of API calls to the IOC_Stream API Endpoint for AI / LLMs to fully understand the different filters and results of the API calls. 

## Example 1: No filters with descriptors_only=false and entity:ip_address
>limited to 1 object for brevity

### Sample Request with descriptors_only=false and entity:ip_address
```
curl --request GET \
     --url 'https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false&filter=entity_type%3Aip_address' \
     --header 'accept: application/json' \
     --header 'x-apikey: <api-key>'
```

### Sample Request with descriptors_only=false and entity:ip_address
```
{
  "data": [
    {
      "id": "1.1.1.1",
      "type": "ip_address",
      "links": {
        "self": "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1"
      },
      "attributes": {
        "total_votes": {
          "harmless": 132,
          "malicious": 36
        },
        "threat_severity": {
          "version": "I3",
          "threat_severity_level": "SEVERITY_NONE",
          "threat_severity_data": {
            "has_bad_communicating_files_high": true,
            "has_bad_communicating_files_medium": true,
            "belongs_to_bad_collection": true
          },
          "last_analysis_date": "1759369591",
          "level_description": "Severity NONE because it has no detections."
        },
        "whois_date": 1759576395,
        "last_https_certificate_date": 1759891614,
        "mandiant_ic_score": 0,
        "as_owner": "CLOUDFLARENET",
        "tags": [
          "suspicious-udp"
        ],
        "jarm": "27d27d27d00027d00042d43d00041df04c41293ba84f6efe3a613b22f983e6",
        "reputation": 76,
        "first_seen_itw_date": 1577959590,
        "rdap": {
          "object_class_name": "ip network",
          "handle": "1.1.1.0 - 1.1.1.255",
          "start_address": "1.1.1.0",
          "end_address": "1.1.1.255",
          "ip_version": "v4",
          "name": "APNIC-LABS",
          "type": "ASSIGNED PORTABLE",
          "country": "AU",
          "status": [
            "active"
          ],
          "links": [
            {
              "href": "https://rdap.apnic.net/ip/1.1.1.0/24",
              "rel": "self",
              "type": "application/rdap+json",
              "value": "https://rdap.apnic.net/ip/1.1.1.1",
              "title": "",
              "media": "",
              "href_lang": []
            }
          ],
          "notices": [
            {
              "title": "Source",
              "description": [
                "Objects returned came from source",
                "APNIC"
              ],
              "links": [],
              "type": ""
            },
            {
              "title": "Terms and Conditions",
              "description": [
                "This is the APNIC WHOIS Database query service. The objects are in RDAP format."
              ],
              "links": [
                {
                  "href": "http://www.apnic.net/db/dbcopyright.html",
                  "rel": "terms-of-service",
                  "type": "text/html",
                  "value": "https://rdap.apnic.net/ip/1.1.1.1",
                  "title": "",
                  "media": "",
                  "href_lang": []
                }
              ],
              "type": ""
            },
            {
              "title": "Whois Inaccuracy Reporting",
              "description": [
                "If you see inaccuracies in the results, please visit: "
              ],
              "links": [
                {
                  "href": "https://www.apnic.net/manage-ip/using-whois/abuse-and-spamming/invalid-contact-form",
                  "rel": "inaccuracy-report",
                  "type": "text/html",
                  "value": "https://rdap.apnic.net/ip/1.1.1.1",
                  "title": "",
                  "media": "",
                  "href_lang": []
                }
              ],
              "type": ""
            }
          ],
          "events": [
            {
              "event_action": "registration",
              "event_date": "2011-08-10T23:12:35Z",
              "event_actor": "",
              "links": []
            },
            {
              "event_action": "last changed",
              "event_date": "2023-04-26T22:57:58Z",
              "event_actor": "",
              "links": []
            }
          ],
          "rdap_conformance": [
            "history_version_0",
            "nro_rdap_profile_0",
            "cidr0",
            "rdap_level_0"
          ],
          "entities": [
            {
              "object_class_name": "entity",
              "handle": "AIC3-AP",
              "vcard_array": [
                {
                  "name": "version",
                  "type": "text",
                  "values": [
                    "4.0"
                  ],
                  "parameters": {}
                },
                {
                  "name": "fn",
                  "type": "text",
                  "values": [
                    "APNICRANDNET Infrastructure Contact"
                  ],
                  "parameters": {}
                },
                {
                  "name": "kind",
                  "type": "text",
                  "values": [
                    "group"
                  ],
                  "parameters": {}
                },
                {
                  "name": "adr",
                  "parameters": {
                    "label": [
                      "6 Cordelia St South Brisbane QLD 4101"
                    ]
                  },
                  "type": "text",
                  "values": [
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    ""
                  ]
                },
                {
                  "name": "tel",
                  "parameters": {
                    "type": [
                      "voice"
                    ]
                  },
                  "type": "text",
                  "values": [
                    "+61 7 3858 3100"
                  ]
                },
                {
                  "name": "email",
                  "type": "text",
                  "values": [
                    "research@apnic.net"
                  ],
                  "parameters": {}
                }
              ],
              "roles": [
                "administrative",
                "technical"
              ],
              "links": [
                {
                  "href": "https://rdap.apnic.net/entity/AIC3-AP",
                  "rel": "self",
                  "type": "application/rdap+json",
                  "value": "https://rdap.apnic.net/ip/1.1.1.1",
                  "title": "",
                  "media": "",
                  "href_lang": []
                }
              ],
              "events": [
                {
                  "event_action": "registration",
                  "event_date": "2023-04-26T00:42:16Z",
                  "event_actor": "",
                  "links": []
                },
                {
                  "event_action": "last changed",
                  "event_date": "2024-07-18T04:37:37Z",
                  "event_actor": "",
                  "links": []
                }
              ],
              "public_ids": [],
              "entities": [],
              "remarks": [],
              "as_event_actor": [],
              "status": [],
              "port43": "",
              "networks": [],
              "autnums": [],
              "url": "",
              "lang": "",
              "rdap_conformance": []
            },
            {
              "object_class_name": "entity",
              "handle": "ORG-ARAD1-AP",
              "vcard_array": [
                {
                  "name": "version",
                  "type": "text",
                  "values": [
                    "4.0"
                  ],
                  "parameters": {}
                },
                {
                  "name": "fn",
                  "type": "text",
                  "values": [
                    "APNIC Research and Development"
                  ],
                  "parameters": {}
                },
                {
                  "name": "kind",
                  "type": "text",
                  "values": [
                    "org"
                  ],
                  "parameters": {}
                },
                {
                  "name": "adr",
                  "parameters": {
                    "label": [
                      "6 Cordelia St"
                    ]
                  },
                  "type": "text",
                  "values": [
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    ""
                  ]
                },
                {
                  "name": "tel",
                  "parameters": {
                    "type": [
                      "voice"
                    ]
                  },
                  "type": "text",
                  "values": [
                    "+61-7-38583100"
                  ]
                },
                {
                  "name": "tel",
                  "parameters": {
                    "type": [
                      "fax"
                    ]
                  },
                  "type": "text",
                  "values": [
                    "+61-7-38583199"
                  ]
                },
                {
                  "name": "email",
                  "type": "text",
                  "values": [
                    "helpdesk@apnic.net"
                  ],
                  "parameters": {}
                }
              ],
              "roles": [
                "registrant"
              ],
              "links": [
                {
                  "href": "https://rdap.apnic.net/entity/ORG-ARAD1-AP",
                  "rel": "self",
                  "type": "application/rdap+json",
                  "value": "https://rdap.apnic.net/ip/1.1.1.1",
                  "title": "",
                  "media": "",
                  "href_lang": []
                }
              ],
              "events": [
                {
                  "event_action": "registration",
                  "event_date": "2017-08-08T23:21:55Z",
                  "event_actor": "",
                  "links": []
                },
                {
                  "event_action": "last changed",
                  "event_date": "2023-09-05T02:15:19Z",
                  "event_actor": "",
                  "links": []
                }
              ],
              "public_ids": [],
              "entities": [],
              "remarks": [],
              "as_event_actor": [],
              "status": [],
              "port43": "",
              "networks": [],
              "autnums": [],
              "url": "",
              "lang": "",
              "rdap_conformance": []
            },
            {
              "object_class_name": "entity",
              "handle": "IRT-APNICRANDNET-AU",
              "vcard_array": [
                {
                  "name": "version",
                  "type": "text",
                  "values": [
                    "4.0"
                  ],
                  "parameters": {}
                },
                {
                  "name": "fn",
                  "type": "text",
                  "values": [
                    "IRT-APNICRANDNET-AU"
                  ],
                  "parameters": {}
                },
                {
                  "name": "kind",
                  "type": "text",
                  "values": [
                    "group"
                  ],
                  "parameters": {}
                },
                {
                  "name": "adr",
                  "parameters": {
                    "label": [
                      "PO Box 3646\nSouth Brisbane, QLD 4101\nAustralia"
                    ]
                  },
                  "type": "text",
                  "values": [
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    ""
                  ]
                },
                {
                  "name": "email",
                  "type": "text",
                  "values": [
                    "helpdesk@apnic.net"
                  ],
                  "parameters": {}
                },
                {
                  "name": "email",
                  "parameters": {
                    "pref": [
                      "1"
                    ]
                  },
                  "type": "text",
                  "values": [
                    "helpdesk@apnic.net"
                  ]
                }
              ],
              "roles": [
                "abuse"
              ],
              "remarks": [
                {
                  "title": "remarks",
                  "description": [
                    "helpdesk@apnic.net was validated on 2021-02-09"
                  ],
                  "links": [],
                  "type": ""
                }
              ],
              "links": [
                {
                  "href": "https://rdap.apnic.net/entity/IRT-APNICRANDNET-AU",
                  "rel": "self",
                  "type": "application/rdap+json",
                  "value": "https://rdap.apnic.net/ip/1.1.1.1",
                  "title": "",
                  "media": "",
                  "href_lang": []
                }
              ],
              "events": [
                {
                  "event_action": "registration",
                  "event_date": "2011-04-12T17:56:54Z",
                  "event_actor": "",
                  "links": []
                },
                {
                  "event_action": "last changed",
                  "event_date": "2025-09-03T02:28:14Z",
                  "event_actor": "",
                  "links": []
                }
              ],
              "public_ids": [],
              "entities": [],
              "as_event_actor": [],
              "status": [],
              "port43": "",
              "networks": [],
              "autnums": [],
              "url": "",
              "lang": "",
              "rdap_conformance": []
            }
          ],
          "port43": "whois.apnic.net",
          "cidr0_cidrs": [
            {
              "v4prefix": "1.1.1.0",
              "length": 24,
              "v6prefix": ""
            }
          ],
          "remarks": [
            {
              "title": "description",
              "description": [
                "APNIC and Cloudflare DNS Resolver project",
                "Routed globally by AS13335/Cloudflare",
                "Research prefix for APNIC Labs"
              ],
              "links": [],
              "type": ""
            },
            {
              "title": "remarks",
              "description": [
                "---------------",
                "All Cloudflare abuse reporting can be done via",
                "resolver-abuse@cloudflare.com",
                "---------------"
              ],
              "links": [],
              "type": ""
            }
          ],
          "parent_handle": "",
          "arin_originas0_originautnums": []
        },
        "last_analysis_results": {
          "Acronis": {
            "method": "blacklist",
            "engine_name": "Acronis",
            "category": "harmless",
            "result": "clean"
          },
          "0xSI_f33d": {
            "method": "blacklist",
            "engine_name": "0xSI_f33d",
            "category": "undetected",
            "result": "unrated"
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
          "Axur": {
            "method": "blacklist",
            "engine_name": "Axur",
            "category": "undetected",
            "result": "unrated"
          },
          "ChainPatrol": {
            "method": "blacklist",
            "engine_name": "ChainPatrol",
            "category": "undetected",
            "result": "unrated"
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
            "category": "harmless",
            "result": "clean"
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
          "Cluster25": {
            "method": "blacklist",
            "engine_name": "Cluster25",
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
          "Snort IP sample list": {
            "method": "blacklist",
            "engine_name": "Snort IP sample list",
            "category": "harmless",
            "result": "clean"
          },
          "CMC Threat Intelligence": {
            "method": "blacklist",
            "engine_name": "CMC Threat Intelligence",
            "category": "harmless",
            "result": "clean"
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
          "Emsisoft": {
            "method": "blacklist",
            "engine_name": "Emsisoft",
            "category": "harmless",
            "result": "clean"
          },
          "Forcepoint ThreatSeeker": {
            "method": "blacklist",
            "engine_name": "Forcepoint ThreatSeeker",
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
          "GCP Abuse Intelligence": {
            "method": "blacklist",
            "engine_name": "GCP Abuse Intelligence",
            "category": "undetected",
            "result": "unrated"
          },
          "Google Safebrowsing": {
            "method": "blacklist",
            "engine_name": "Google Safebrowsing",
            "category": "harmless",
            "result": "clean"
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
          "Lionic": {
            "method": "blacklist",
            "engine_name": "Lionic",
            "category": "harmless",
            "result": "clean"
          },
          "Lumu": {
            "method": "blacklist",
            "engine_name": "Lumu",
            "category": "undetected",
            "result": "unrated"
          },
          "MalwarePatrol": {
            "method": "blacklist",
            "engine_name": "MalwarePatrol",
            "category": "harmless",
            "result": "clean"
          },
          "MalwareURL": {
            "method": "blacklist",
            "engine_name": "MalwareURL",
            "category": "undetected",
            "result": "unrated"
          },
          "Malwared": {
            "method": "blacklist",
            "engine_name": "Malwared",
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
          "SafeToOpen": {
            "method": "blacklist",
            "engine_name": "SafeToOpen",
            "category": "undetected",
            "result": "unrated"
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
          "SecureBrain": {
            "method": "blacklist",
            "engine_name": "SecureBrain",
            "category": "undetected",
            "result": "unrated"
          },
          "SOCRadar": {
            "method": "blacklist",
            "engine_name": "SOCRadar",
            "category": "harmless",
            "result": "clean"
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
          "ThreatHive": {
            "method": "blacklist",
            "engine_name": "ThreatHive",
            "category": "harmless",
            "result": "clean"
          },
          "Threatsourcing": {
            "method": "blacklist",
            "engine_name": "Threatsourcing",
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
          "VX Vault": {
            "method": "blacklist",
            "engine_name": "VX Vault",
            "category": "harmless",
            "result": "clean"
          },
          "ViriBack": {
            "method": "blacklist",
            "engine_name": "ViriBack",
            "category": "harmless",
            "result": "clean"
          },
          "Webroot": {
            "method": "blacklist",
            "engine_name": "Webroot",
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
          "desenmascara.me": {
            "method": "blacklist",
            "engine_name": "desenmascara.me",
            "category": "harmless",
            "result": "clean"
          },
          "malwares.com URL checker": {
            "method": "blacklist",
            "engine_name": "malwares.com URL checker",
            "category": "harmless",
            "result": "clean"
          },
          "securolytics": {
            "method": "blacklist",
            "engine_name": "securolytics",
            "category": "harmless",
            "result": "clean"
          },
          "Xcitium Verdict Cloud": {
            "method": "blacklist",
            "engine_name": "Xcitium Verdict Cloud",
            "category": "undetected",
            "result": "unrated"
          },
          "zvelo": {
            "method": "blacklist",
            "engine_name": "zvelo",
            "category": "undetected",
            "result": "unrated"
          },
          "ZeroFox": {
            "method": "blacklist",
            "engine_name": "ZeroFox",
            "category": "undetected",
            "result": "unrated"
          }
        },
        "last_analysis_date": 1759891313,
        "last_analysis_stats": {
          "malicious": 0,
          "suspicious": 0,
          "undetected": 31,
          "harmless": 64,
          "timeout": 0
        },
        "last_https_certificate": {
          "cert_signature": {
            "signature_algorithm": "sha256RSA",
            "signature": "9c36c4801745f127ad4635a3a78c80945dea3fe1eec0dfe09e1ad1c618232aae043b1150e697d7641059c9a8a2f0ffa5a68e0a3b0464e898c77baedbcfe7d1a3de4b1f5d73eb53c13b279e4eb2c3b6d0d76779c26da86e754e979d76616e98a37c1dfbd8592a5b51f874e989e00b23abf26054a294f46e5b33fc8dd0c564f3d3636c4cca88467c5e4bd5e4e171e3a3bc627e4b5ccffa40cd991f607c2cb97b8ad2fde6b3a3a8eb27e241b2e94417358438c5f9eb7dd5646c19d73d885f1e1d3d6beb9ec422be8aab5a4cf1a9c96bb8fd47dc22a69c316f51266f976b3a088673136af448c8cd72541427185f836b48097755e0b623c76e25684cd9571a0213e6"
          },
          "extensions": {
            "authority_key_identifier": {
              "keyid": "748580c066c7df37decfbd2937aa031dbeedcd17"
            },
            "subject_key_identifier": "2b2f8483a3e669e954c0e5b0b69f1fcdb618afa8",
            "subject_alternative_name": [
              "cloudflare-dns.com",
              "*.cloudflare-dns.com",
              "one.one.one.one",
              "1.0.0.1",
              "1.1.1.1",
              "162.159.36.1",
              "162.159.46.1",
              "2606:4700:4700::1001",
              "2606:4700:4700::1111",
              "2606:4700:4700::64",
              "2606:4700:4700::6400"
            ],
            "certificate_policies": [
              "2.23.140.1.2.2"
            ],
            "key_usage": [
              "digitalSignature",
              "keyAgreement"
            ],
            "extended_key_usage": [
              "serverAuth",
              "clientAuth"
            ],
            "crl_distribution_points": [
              "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
              "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl"
            ],
            "ca_information_access": {
              "OCSP": "http://ocsp.digicert.com",
              "CA Issuers": "http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt"
            },
            "CA": false,
            "1.3.6.1.4.1.11129.2.4.2": "0482016901670075000e5794bcf3aea93e331b2c9907b3f790df9bc23d713225"
          },
          "validity": {
            "not_after": "2026-01-21 23:59:59",
            "not_before": "2025-01-02 00:00:00"
          },
          "size": 1703,
          "version": "V3",
          "public_key": {
            "algorithm": "EC",
            "ec": {
              "oid": "secp256r1",
              "pub": "3059301306072a8648ce3d020106082a8648ce3d030107034200048080f1decb9302a3407e95b2b9ea4f7fcba332c63c32e360027a828d372607076b402e4e099b1697363fa3f295ee029bd4a1b4b58c942e9146798cea5b86ca86"
            }
          },
          "thumbprint_sha256": "73b8ed5becf1ba6493d2e2215a42dfdc7877e91e311ff5e59fb43d094871e699",
          "thumbprint": "3ba7e9f806eb30d2f4e3f905e53f07e9acf08e1e",
          "serial_number": "27dc8c5e17294aec9ed3f67728e8a08",
          "issuer": {
            "C": "US",
            "O": "DigiCert Inc",
            "CN": "DigiCert Global G2 TLS RSA SHA256 2020 CA1"
          },
          "subject": {
            "C": "US",
            "ST": "California",
            "L": "San Francisco",
            "O": "Cloudflare, Inc.",
            "CN": "cloudflare-dns.com"
          }
        },
        "whois": "NetRange: 1.0.0.0 - 1.255.255.255\nCIDR: 1.0.0.0/8\nNetName: APNIC-1\nNetHandle: NET-1-0-0-0-1\nParent: ()\nNetType: Allocated to APNIC\nOriginAS: \nOrganization: Asia Pacific Network Information Centre (APNIC)\nRegDate: \nUpdated: 2010-07-30\nComment: This IP address range is not registered in the ARIN database.\nComment: For details, refer to the APNIC Whois Database via\nComment: WHOIS.APNIC.NET or http://wq.apnic.net/apnic-bin/whois.pl\nComment: ** IMPORTANT NOTE: APNIC is the Regional Internet Registry\nComment: for the Asia Pacific region. APNIC does not operate networks\nComment: using this IP address range and is not able to investigate\nComment: spam or abuse reports relating to these addresses. For more\nComment: help, refer to http://www.apnic.net/apnic-info/whois_search2/abuse-and-spamming\nRef: https://rdap.arin.net/registry/ip/1.0.0.0\nResourceLink: https://apps.db.ripe.net/db-web-ui/query\nResourceLink: whois.apnic.net\nOrgName: Asia Pacific Network Information Centre\nOrgId: APNIC\nAddress: PO Box 3646\nCity: South Brisbane\nStateProv: QLD\nPostalCode: 4101\nCountry: AU\nRegDate: \nUpdated: 2012-01-24\nRef: https://rdap.arin.net/registry/entity/APNIC\nReferralServer: whois://whois.apnic.net\nResourceLink: https://apps.db.ripe.net/db-web-ui/query\nOrgAbuseHandle: AWC12-ARIN\nOrgAbuseName: APNIC Whois Contact\nOrgAbusePhone: +61 7 3858 3188 \nOrgAbuseEmail: search-apnic-not-arin@apnic.net\nOrgAbuseRef: https://rdap.arin.net/registry/entity/AWC12-ARIN\nOrgTechHandle: AWC12-ARIN\nOrgTechName: APNIC Whois Contact\nOrgTechPhone: +61 7 3858 3188 \nOrgTechEmail: search-apnic-not-arin@apnic.net\nOrgTechRef: https://rdap.arin.net/registry/entity/AWC12-ARIN\ninetnum: 1.1.1.0 - 1.1.1.255\nnetname: APNIC-LABS\ndescr: APNIC and Cloudflare DNS Resolver project\ndescr: Routed globally by AS13335/Cloudflare\ndescr: Research prefix for APNIC Labs\ncountry: AU\norg: ORG-ARAD1-AP\nadmin-c: AIC3-AP\ntech-c: AIC3-AP\nabuse-c: AA1412-AP\nstatus: ASSIGNED PORTABLE\nremarks: ---------------\nremarks: All Cloudflare abuse reporting can be done via\nremarks: resolver-abuse@cloudflare.com\nremarks: ---------------\nmnt-by: APNIC-HM\nmnt-routes: MAINT-APNICRANDNET\nmnt-irt: IRT-APNICRANDNET-AU\nlast-modified: 2023-04-26T22:57:58Z\nmnt-lower: MAINT-APNICRANDNET\nsource: APNIC\nirt: IRT-APNICRANDNET-AU\naddress: PO Box 3646\naddress: South Brisbane, QLD 4101\naddress: Australia\ne-mail: helpdesk@apnic.net\nabuse-mailbox: helpdesk@apnic.net\nadmin-c: AR302-AP\ntech-c: AR302-AP\nauth: # Filtered\nremarks: helpdesk@apnic.net was validated on 2021-02-09\nmnt-by: MAINT-APNICRANDNET\nlast-modified: 2025-09-03T02:28:14Z\nsource: APNIC\norganisation: ORG-ARAD1-AP\norg-name: APNIC Research and Development\norg-type: LIR\ncountry: AU\naddress: 6 Cordelia St\nphone: +61-7-38583100\nfax-no: +61-7-38583199\ne-mail: helpdesk@apnic.net\nmnt-ref: APNIC-HM\nmnt-by: APNIC-HM\nlast-modified: 2023-09-05T02:15:19Z\nsource: APNIC\nrole: ABUSE APNICRANDNETAU\ncountry: ZZ\naddress: PO Box 3646\naddress: South Brisbane, QLD 4101\naddress: Australia\nphone: +000000000\ne-mail: helpdesk@apnic.net\nadmin-c: AR302-AP\ntech-c: AR302-AP\nnic-hdl: AA1412-AP\nremarks: Generated from irt object IRT-APNICRANDNET-AU\nremarks: helpdesk@apnic.net was validated on 2021-02-09\nabuse-mailbox: helpdesk@apnic.net\nmnt-by: APNIC-ABUSE\nlast-modified: 2025-05-28T03:31:35Z\nsource: APNIC\nrole: APNICRANDNET Infrastructure Contact\naddress: 6 Cordelia St\n South Brisbane\n QLD 4101\ncountry: AU\nphone: +61 7 3858 3100\ne-mail: research@apnic.net\nadmin-c: AIC3-AP\ntech-c: AIC3-AP\nnic-hdl: AIC3-AP\nmnt-by: MAINT-APNICRANDNET\nlast-modified: 2024-07-18T04:37:37Z\nsource: APNIC\nroute: 1.1.1.0/24\norigin: AS13335\ndescr: APNIC Research and Development\n 6 Cordelia St\nmnt-by: MAINT-APNICRANDNET\nlast-modified: 2023-04-26T02:42:44Z\nsource: APNIC\n",
        "last_modification_date": 1759897898,
        "asn": 13335,
        "network": "1.1.1.0/24",
        "last_seen_itw_date": 1759119383
      },
      "context_attributes": {
        "notification_id": "23413591649",
        "origin": "hunting",
        "notification_date": 1759895184,
        "sources": [
          {
            "id": "19229266859",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_IPMaliciousFiles"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_ipmaliciousfiles",
          "ipservesmaliciousfile"
        ],
        "hunting_info": {
          "rule_name": "IPServesMaliciousFile",
          "match_source": "IP_ADDRESS"
        }
      }
    }
  ],
  "meta": {
    "cursor": "eJwNy9FugyAUANBfQhxLX9soriwXJiKIb1a7rnBtcNkyZ_bx8_E8nL--w9cJ05d7pMFxngxNp5Hgd_3AO2Tpx8XJXVtcLhQbHUXbOMwHB7-qw1iTSG2eOBDWDpt-s9w-GaL1_pemS0qX9tmg_ryWbGmNFZeiZO8vK4V8PYAZM2VuTG43prr14MNpllUfwPE7VCKC6T92rZ6Wmao0ShMZbEcGIVK5TUEGgRA0qmIkMNeZnz3bD3ojZlXsx50pHP8BVwhKfQ==",
    "count": 922
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false&filter=entity_type:ip_address",
    "next": "https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false&filter=entity_type%3Aip_address&cursor=eJwNy9FugyAUANBfQhxLX9soriwXJiKIb1a7rnBtcNkyZ_bx8_E8nL--w9cJ05d7pMFxngxNp5Hgd_3AO2Tpx8XJXVtcLhQbHUXbOMwHB7-qw1iTSG2eOBDWDpt-s9w-GaL1_pemS0qX9tmg_ryWbGmNFZeiZO8vK4V8PYAZM2VuTG43prr14MNpllUfwPE7VCKC6T92rZ6Wmao0ShMZbEcGIVK5TUEGgRA0qmIkMNeZnz3bD3ojZlXsx50pHP8BVwhKfQ%3D%3D"
  }
}
```