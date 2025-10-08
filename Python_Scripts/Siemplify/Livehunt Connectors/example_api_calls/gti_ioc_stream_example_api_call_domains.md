# A list of API calls from IOC Stream for Domains
A list of API calls to the IOC_Stream API Endpoint for AI / LLMs to fully understand the different filters and results of the API calls. 

## Example 1: No filters with descriptors_only=false and entity:domains
>limited to 1 object for brevity

### Sample Request with descriptors_only=false and entity:domains
```
curl --request GET \
     --url 'https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false&filter=entity_type%3Adomain' \
     --header 'accept: application/json' \
     --header 'x-apikey: <api-key>'
```

### Sample Request with descriptors_only=false and entity:domain
```
{
  "data": [
    {
      "id": "ncxx.dl6.cn",
      "type": "domain",
      "links": {
        "self": "https://www.virustotal.com/api/v3/domains/ncxx.dl6.cn"
      },
      "attributes": {
        "last_dns_records": [
          {
            "type": "A",
            "ttl": 600,
            "value": "1.1.1.1"
          }
        ],
        "last_analysis_stats": {
          "malicious": 0,
          "suspicious": 0,
          "undetected": 95,
          "harmless": 0,
          "timeout": 0
        },
        "tags": [],
        "reputation": 0,
        "last_https_certificate_date": 1759890723,
        "categories": {},
        "popularity_ranks": {},
        "threat_severity": {
          "version": "D3",
          "threat_severity_level": "SEVERITY_NONE",
          "threat_severity_data": {},
          "last_analysis_date": "1759890723",
          "level_description": "No severity score data"
        },
        "last_modification_date": 1759890724,
        "total_votes": {
          "harmless": 0,
          "malicious": 0
        },
        "last_dns_records_date": 1759890723,
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
        "whois": "DNSSEC: unsigned\nDomain Name: dl6.cn\nDomain Status: ok\nExpiration Time: 2025-06-02 04:07:35\nName Server: pk3.22.cn\nName Server: pk4.22.cn\nRegistrant Contact Email: 2bee5632439a6215s@qq.com\nRegistrant: 40fbdc9eb6185b9b\nRegistration Time: 2024-06-02 04:07:35\nSponsoring Registrar: 温州市中网计算机技术服务有限公司",
        "jarm": "27d27d27d00027d00042d43d00041df04c41293ba84f6efe3a613b22f983e6",
        "last_analysis_date": 1759890719,
        "last_analysis_results": {
          "Acronis": {
            "method": "blacklist",
            "engine_name": "Acronis",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "ADMINUSLabs": {
            "method": "blacklist",
            "engine_name": "ADMINUSLabs",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "AILabs (MONITORAPP)": {
            "method": "blacklist",
            "engine_name": "AILabs (MONITORAPP)",
            "category": "undetected",
            "result": "unrated"
          },
          "AlienVault": {
            "method": "blacklist",
            "engine_name": "AlienVault",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "Certego": {
            "method": "blacklist",
            "engine_name": "Certego",
            "category": "undetected",
            "result": "unrated"
          },
          "Chong Lua Dao": {
            "method": "blacklist",
            "engine_name": "Chong Lua Dao",
            "category": "undetected",
            "result": "unrated"
          },
          "CINS Army": {
            "method": "blacklist",
            "engine_name": "CINS Army",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "CMC Threat Intelligence": {
            "method": "blacklist",
            "engine_name": "CMC Threat Intelligence",
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
            "category": "undetected",
            "result": "unrated"
          },
          "CyRadar": {
            "method": "blacklist",
            "engine_name": "CyRadar",
            "category": "undetected",
            "result": "unrated"
          },
          "DNS8": {
            "method": "blacklist",
            "engine_name": "DNS8",
            "category": "undetected",
            "result": "unrated"
          },
          "Dr.Web": {
            "method": "blacklist",
            "engine_name": "Dr.Web",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "ESTsecurity": {
            "method": "blacklist",
            "engine_name": "ESTsecurity",
            "category": "undetected",
            "result": "unrated"
          },
          "EmergingThreats": {
            "method": "blacklist",
            "engine_name": "EmergingThreats",
            "category": "undetected",
            "result": "unrated"
          },
          "Emsisoft": {
            "method": "blacklist",
            "engine_name": "Emsisoft",
            "category": "undetected",
            "result": "unrated"
          },
          "Forcepoint ThreatSeeker": {
            "method": "blacklist",
            "engine_name": "Forcepoint ThreatSeeker",
            "category": "undetected",
            "result": "unrated"
          },
          "Fortinet": {
            "method": "blacklist",
            "engine_name": "Fortinet",
            "category": "undetected",
            "result": "unrated"
          },
          "G-Data": {
            "method": "blacklist",
            "engine_name": "G-Data",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "GreenSnow": {
            "method": "blacklist",
            "engine_name": "GreenSnow",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "Juniper Networks": {
            "method": "blacklist",
            "engine_name": "Juniper Networks",
            "category": "undetected",
            "result": "unrated"
          },
          "Kaspersky": {
            "method": "blacklist",
            "engine_name": "Kaspersky",
            "category": "undetected",
            "result": "unrated"
          },
          "Lionic": {
            "method": "blacklist",
            "engine_name": "Lionic",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "Phishing Database": {
            "method": "blacklist",
            "engine_name": "Phishing Database",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "PREBYTES": {
            "method": "blacklist",
            "engine_name": "PREBYTES",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "Quttera": {
            "method": "blacklist",
            "engine_name": "Quttera",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "SCUMWARE.org": {
            "method": "blacklist",
            "engine_name": "SCUMWARE.org",
            "category": "undetected",
            "result": "unrated"
          },
          "Seclookup": {
            "method": "blacklist",
            "engine_name": "Seclookup",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "Sophos": {
            "method": "blacklist",
            "engine_name": "Sophos",
            "category": "undetected",
            "result": "unrated"
          },
          "Spam404": {
            "method": "blacklist",
            "engine_name": "Spam404",
            "category": "undetected",
            "result": "unrated"
          },
          "StopForumSpam": {
            "method": "blacklist",
            "engine_name": "StopForumSpam",
            "category": "undetected",
            "result": "unrated"
          },
          "Sucuri SiteCheck": {
            "method": "blacklist",
            "engine_name": "Sucuri SiteCheck",
            "category": "undetected",
            "result": "unrated"
          },
          "ThreatHive": {
            "method": "blacklist",
            "engine_name": "ThreatHive",
            "category": "undetected",
            "result": "unrated"
          },
          "Threatsourcing": {
            "method": "blacklist",
            "engine_name": "Threatsourcing",
            "category": "undetected",
            "result": "unrated"
          },
          "Trustwave": {
            "method": "blacklist",
            "engine_name": "Trustwave",
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
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
            "category": "undetected",
            "result": "unrated"
          },
          "ViriBack": {
            "method": "blacklist",
            "engine_name": "ViriBack",
            "category": "undetected",
            "result": "unrated"
          },
          "Webroot": {
            "method": "blacklist",
            "engine_name": "Webroot",
            "category": "undetected",
            "result": "unrated"
          },
          "Yandex Safebrowsing": {
            "method": "blacklist",
            "engine_name": "Yandex Safebrowsing",
            "category": "undetected",
            "result": "unrated"
          },
          "ZeroCERT": {
            "method": "blacklist",
            "engine_name": "ZeroCERT",
            "category": "undetected",
            "result": "unrated"
          },
          "desenmascara.me": {
            "method": "blacklist",
            "engine_name": "desenmascara.me",
            "category": "undetected",
            "result": "unrated"
          },
          "malwares.com URL checker": {
            "method": "blacklist",
            "engine_name": "malwares.com URL checker",
            "category": "undetected",
            "result": "unrated"
          },
          "securolytics": {
            "method": "blacklist",
            "engine_name": "securolytics",
            "category": "undetected",
            "result": "unrated"
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
        "tld": "cn"
      },
      "context_attributes": {
        "notification_id": "23411729305",
        "origin": "hunting",
        "notification_date": 1759897925,
        "sources": [
          {
            "id": "17661460179",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_IPNewDomains"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_ipnewdomains",
          "newdomainsipsrange"
        ],
        "hunting_info": {
          "rule_name": "newDomainsIPsrange",
          "match_source": "DOMAIN"
        }
      }
    }
  ],
  "meta": {
    "cursor": "eJwNi1FvgyAURv-S4Fz6ukZd63Jh6gWEN6tbW0BDky1ash8_nk5OvvP9mcF_zD78qDWMqq4D0nCcMv_brv4OJGzKzepL-MeF-r5zjeiVz0cFTz5412aOyjzUkBVijN2nfAeCKsj0f_RD4F0lX3ANDRPktcW6uZRV8X3aKeT7AXAiHK8FL982ftoPBuVN2ypqKh1Etxk87xpv1qRd23nRFDJtp6jtmbAy-SIIw0SVejQWoniyRB3Nwsp6gZj66z-NSUx3",
    "count": 341
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false&filter=entity_type:domain",
    "next": "https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false&filter=entity_type%3Adomain&cursor=eJwNi1FvgyAURv-S4Fz6ukZd63Jh6gWEN6tbW0BDky1ash8_nk5OvvP9mcF_zD78qDWMqq4D0nCcMv_brv4OJGzKzepL-MeF-r5zjeiVz0cFTz5412aOyjzUkBVijN2nfAeCKsj0f_RD4F0lX3ANDRPktcW6uZRV8X3aKeT7AXAiHK8FL982ftoPBuVN2ypqKh1Etxk87xpv1qRd23nRFDJtp6jtmbAy-SIIw0SVejQWoniyRB3Nwsp6gZj66z-NSUx3"
  }
}
```
