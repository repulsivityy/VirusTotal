# A list of API calls from IOC Stream  
A list of API calls to the IOC_Stream API Endpoint for AI / LLMs to fully understand the different filters and results of the API calls. 


## Example 1: No filters with descriptors_only=true
>Only limiting the responses to 5 objects for brevity. 

### Sample Request with descriptors_only=true
```
curl --request GET \
     --header 'accept: application/json' \
     --url 'https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true' \
     --header 'x-apikey: <api-key>'
```

### Sample Response with descriptors_only=true
```
{
  "data": [
    {
      "type": "file",
      "id": "e614e730ac8fe533252c8e5d136ced67ead32e6f6d13c79c596db67cb785354e",
      "context_attributes": {
        "notification_id": "23415549505",
        "origin": "hunting",
        "notification_date": 1759893105,
        "sources": [
          {
            "id": "20136027621",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_PotentialIntDocsContent"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_potentialintdocscontent",
          "potentialintdocscontent"
        ],
        "hunting_info": {
          "rule_name": "potentialIntDocsContent",
          "source_key": "af632c50",
          "source_country": "US",
          "snippet": "A0 00 6E DC 68 3A C3 06 4B 4C 5D 06 45 D0 4D E3  ..n.h:..KL].E.M.\n0D 00 6C 79 *begin_highlight*49 6E 43 *end_highlight*65 6C 6C 9B 30 0E 6E 17 27  ..ly*begin_highlight*InC*end_highlight*ell.0.n.'\nC6 06 E0 73 65 72 89 05 9F 81 50 4D 05 EC 13 1F  ...ser....PM....\n65 64 44 65 63 69 6D 61 6C 6A A5 10 00 12 00 45  edDecimalj.....E\n64 69 74 44 69 72 65 63 74 6C 79 *begin_highlight*49 6E 43 *end_highlight*65 6C  ditDirectly*begin_highlight*InC*end_highlight*el\n6C 94 57 10 00 0F 00 4D 6F 76 65 41 66 74 65 72  l.W....MoveAfter",
          "match_source": "ORIGINAL_FILE"
        }
      }
    },
    {
      "type": "file",
      "id": "bfa0fb5d456957a9d18e7a6c7b3f0e04df55764bb28982b7b62e339093ee59fc",
      "context_attributes": {
        "notification_id": "23444250870",
        "origin": "hunting",
        "notification_date": 1759893100,
        "sources": [
          {
            "id": "20136027621",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_PotentialIntDocsContent"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_potentialintdocscontent",
          "potentialintdocscontent"
        ],
        "hunting_info": {
          "rule_name": "potentialIntDocsContent",
          "source_key": "2269ef75",
          "source_country": "US",
          "snippet": "69 6E 0A 31 32 20 64 69 63 74 20 62 65 67 69 6E  in.12 dict begin\n0A 62 65 67 *begin_highlight*69 6E 63 *end_highlight*6D 61 70 0A 2F 43 49 44 53  .beg*begin_highlight*inc*end_highlight*map./CIDS\n79 73 74 65 6D 49 6E 66 6F 20 3C 3C 20 2F 52 65  ystemInfo << /Re\n53 20 64 65 66 0A 2F 43 4D 61 70 54 79 70 65 20  S def./CMapType \n32 20 64 65 66 0A 31 20 62 65 67 *begin_highlight*69 6E 63 *end_highlight*6F 64  2 def.1 beg*begin_highlight*inc*end_highlight*od\n65 73 70 61 63 65 72 61 6E 67 65 0A 3C 30 30 30  espacerange.<000\n20 62 65 67 69 6E 0A 31 32 20 64 69 63 74 20 62   begin.12 dict b\n65 67 69 6E 0A 62 65 67 *begin_highlight*69 6E 63 *end_highlight*6D 61 70 0A 2F  egin.beg*begin_highlight*inc*end_highlight*map./\n43 49 44 53 79 73 74 65 6D 49 6E 66 6F 20 3C 3C  CIDSystemInfo <<\n79 2D 55 43 53 20 64 65 66 0A 2F 43 4D 61 70 54  y-UCS def./CMapT\n79 70 65 20 32 20 64 65 66 0A 31 20 62 65 67 *begin_highlight*69*end_highlight*  ype 2 def.1 beg*begin_highlight*i*end_highlight*\n*begin_highlight*6E 63 *end_highlight*6F 64 65 73 70 61 63 65 72 61 6E 67 65 0A  *begin_highlight*nc*end_highlight*odespacerange.",
          "match_source": "ORIGINAL_FILE"
        }
      }
    },
    {
      "type": "file",
      "id": "407465e4a913d5be1fcf48689da8c457258faf40f02b0718cc52fe8f4174f0df",
      "context_attributes": {
        "notification_id": "23417063379",
        "origin": "hunting",
        "notification_date": 1759893098,
        "sources": [
          {
            "id": "20136027621",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_PotentialIntDocsContent"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_potentialintdocscontent",
          "potentialintdocscontent"
        ],
        "hunting_info": {
          "rule_name": "potentialIntDocsContent",
          "source_key": "5b63b993",
          "source_country": "CO",
          "snippet": "42 67 63 49 43 51 6F 4C 45 41 41 43 41 51 4D 44  BgcICQoLEAACAQMD\n41 67 51 43 42 67 63 44 42 *begin_highlight*41 49 47 *end_highlight*41 6E 4D 42  AgQCBgcDB*begin_highlight*AIG*end_highlight*AnMB\n41 67 4D 52 42 41 41 46 49 52 49 78 51 56 45 47  AgMRBAAFIRIxQVEG\n0D E6 36 C5 59 CA 9A 5D 0D DB 2C 8A F8 2F F3 E5  ..6.Y..]..,../..\n92 63 *begin_highlight*49 6E 43 *end_highlight*D1 B9 57 51 1B 30 20 EA AF 95 78  .c*begin_highlight*InC*end_highlight*..WQ.0 ...x\n01 0D 03 1E 34 0C B4 F7 3F B0 2E 0F 15 2F A2 B2  ....4...?..../..",
          "match_source": "ORIGINAL_FILE"
        }
      }
    },
    {
      "type": "file",
      "id": "d4285192e542f78af91e43662f4fb5bc009c3b74db285ab01aeb9c00fc016a96",
      "context_attributes": {
        "notification_id": "23440091616",
        "origin": "hunting",
        "notification_date": 1759893079,
        "sources": [
          {
            "id": "20136027621",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_PotentialIntDocsContent"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_potentialintdocscontent",
          "potentialintdocscontent"
        ],
        "hunting_info": {
          "rule_name": "potentialIntDocsContent",
          "source_key": "2269ef75",
          "source_country": "US",
          "snippet": "72 63 65 20 62 65 67 69 6E 0A 31 32 20 64 69 63  rce begin.12 dic\n74 20 62 65 67 69 6E 0A 62 65 67 *begin_highlight*69 6E 63 *end_highlight*6D 61  t begin.beg*begin_highlight*inc*end_highlight*ma\n70 0A 2F 43 49 44 53 79 73 74 65 6D 49 6E 66 6F  p./CIDSystemInfo\n61 70 54 79 70 65 20 32 20 64 65 66 0A 31 20 62  apType 2 def.1 b\n65 67 *begin_highlight*69 6E 63 *end_highlight*6F 64 65 73 70 61 63 65 72 61 6E  eg*begin_highlight*inc*end_highlight*odespaceran\n67 65 0A 3C 30 30 30 30 3E 20 3C 46 46 46 46 3E  ge.<0000> <FFFF>\n62 65 67 69 6E 0A 31 32 20 64 69 63 74 20 62 65  begin.12 dict be\n67 69 6E 0A 62 65 67 *begin_highlight*69 6E 63 *end_highlight*6D 61 70 0A 2F 43  gin.beg*begin_highlight*inc*end_highlight*map./C\n49 44 53 79 73 74 65 6D 49 6E 66 6F 20 3C 3C 20  IDSystemInfo << \n2D 55 43 53 20 64 65 66 0A 2F 43 4D 61 70 54 79  -UCS def./CMapTy\n70 65 20 32 20 64 65 66 0A 31 20 62 65 67 *begin_highlight*69 6E*end_highlight*  pe 2 def.1 beg*begin_highlight*in*end_highlight*\n*begin_highlight*63 *end_highlight*6F 64 65 73 70 61 63 65 72 61 6E 67 65 0A 3C  *begin_highlight*c*end_highlight*odespacerange.<",
          "match_source": "ORIGINAL_FILE"
        }
      }
    },
    {
      "type": "file",
      "id": "488a5f2d54fca884b32c8bb8a6eb00000fd0ba1b31d9674ba3674e1c6292fd0f",
      "context_attributes": {
        "notification_id": "23435122097",
        "origin": "hunting",
        "notification_date": 1759893077,
        "sources": [
          {
            "id": "20136027621",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_PotentialIntDocsContent"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_potentialintdocscontent",
          "potentialintdocscontent"
        ],
        "hunting_info": {
          "rule_name": "potentialIntDocsContent",
          "source_key": "2269ef75",
          "source_country": "US",
          "snippet": "00 FF FE 00 1F 4C 45 41 44 20 54 65 63 68 6E 6F  .....LEAD Techno\n6C 6F 67 69 65 73 20 *begin_highlight*49 6E 63 *end_highlight*2E 20 56 31 2E 30  logies *begin_highlight*Inc*end_highlight*. V1.0\n31 00 FF DB 00 43 00 03 02 02 02 02 02 03 02 02  1....C..........",
          "match_source": "ORIGINAL_FILE"
        }
      }
    }
  ],
  "meta": {
    "cursor": "eJwVzF1vgyAYhuG_hBCTHi9CF5cXJvIhPbO2cwIzNNkiJfvxY6dPruf-vUzx7RbTt93TbBlLCqeXBcWfYY8bNOmw4WbvOj6uOI4y9Hq0kcwWnmKKYUABG5IYoFbPRb4b2hC1J1__j3FKQlKUlZH9XTd0Lry_drT9eM0YSD6BWhqh1hYKPcSUT-Kss1DSQ1mRqH3w0TtvNoeZBz_kfyuU-YLy6Tmmx0U55KrlHQ-iY5uzdeuWJz9TUu3h1IJh_QOtQkwM",
    "count": 100640
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true",
    "next": "https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&cursor=eJwVzF1vgyAYhuG_hBCTHi9CF5cXJvIhPbO2cwIzNNkiJfvxY6dPruf-vUzx7RbTt93TbBlLCqeXBcWfYY8bNOmw4WbvOj6uOI4y9Hq0kcwWnmKKYUABG5IYoFbPRb4b2hC1J1__j3FKQlKUlZH9XTd0Lry_drT9eM0YSD6BWhqh1hYKPcSUT-Kss1DSQ1mRqH3w0TtvNoeZBz_kfyuU-YLy6Tmmx0U55KrlHQ-iY5uzdeuWJz9TUu3h1IJh_QOtQkwM"
  }
}
```

## Example 2: No filters with descriptors_only=false
>limited to 1 object for brevity

### Sample Request with descriptors_only=false
```
curl --request GET \
     --url 'https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false' \
     --header 'accept: application/json' \
     --header 'x-apikey: <api-key>'
```

### Sample Request with descriptors_only=false
```
{
  "data": [
    {
      "id": "dd9f06f323e3cff8edc24d2627b9a4c98ef06b938450c672c27d1c760742bfd9",
      "type": "file",
      "links": {
        "self": "https://www.virustotal.com/api/v3/files/dd9f06f323e3cff8edc24d2627b9a4c98ef06b938450c672c27d1c760742bfd9"
      },
      "attributes": {
        "sha1": "4175cc678fa4120d2c389d2a2b428e4f8b16023e",
        "reputation": 0,
        "last_analysis_date": 1759890259,
        "meaningful_name": "gradle-5.5-rc-3/subprojects/dependency-management/src/test/groovy/org/gradle/api/internal/artifacts/transform/TransformingAsyncArtifactListenerTest.groovy",
        "last_analysis_results": {
          "Bkav": {
            "method": "blacklist",
            "engine_name": "Bkav",
            "engine_version": "2.0.0.1",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Lionic": {
            "method": "blacklist",
            "engine_name": "Lionic",
            "engine_version": "8.16",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "MicroWorld-eScan": {
            "method": "blacklist",
            "engine_name": "MicroWorld-eScan",
            "engine_version": "14.0.409.0",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "CTX": {
            "method": "blacklist",
            "engine_name": "CTX",
            "engine_version": "2024.8.29.1",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "CAT-QuickHeal": {
            "method": "blacklist",
            "engine_name": "CAT-QuickHeal",
            "engine_version": "22.00",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Skyhigh": {
            "method": "blacklist",
            "engine_name": "Skyhigh",
            "engine_version": "v2021.2.0+4045",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "ALYac": {
            "method": "blacklist",
            "engine_name": "ALYac",
            "engine_version": "2.0.0.10",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Malwarebytes": {
            "method": "blacklist",
            "engine_name": "Malwarebytes",
            "engine_version": "3.1.0.168",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Zillya": {
            "method": "blacklist",
            "engine_name": "Zillya",
            "engine_version": "2.0.0.5461",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Sangfor": {
            "method": "blacklist",
            "engine_name": "Sangfor",
            "engine_version": "2.22.3.0",
            "engine_update": "20251006",
            "category": "undetected",
            "result": null
          },
          "CrowdStrike": {
            "method": "blacklist",
            "engine_name": "CrowdStrike",
            "engine_version": "1.0",
            "engine_update": "20230417",
            "category": "undetected",
            "result": null
          },
          "K7GW": {
            "method": "blacklist",
            "engine_name": "K7GW",
            "engine_version": "14.12.57257",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "K7AntiVirus": {
            "method": "blacklist",
            "engine_name": "K7AntiVirus",
            "engine_version": "14.12.57257",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Baidu": {
            "method": "blacklist",
            "engine_name": "Baidu",
            "engine_version": "1.0.0.2",
            "engine_update": "20190318",
            "category": "undetected",
            "result": null
          },
          "VirIT": {
            "method": "blacklist",
            "engine_name": "VirIT",
            "engine_version": "9.5.1057",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Symantec": {
            "method": "blacklist",
            "engine_name": "Symantec",
            "engine_version": "1.22.0.0",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "ESET-NOD32": {
            "method": "blacklist",
            "engine_name": "ESET-NOD32",
            "engine_version": "31986",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "TrendMicro-HouseCall": {
            "method": "blacklist",
            "engine_name": "TrendMicro-HouseCall",
            "engine_version": "24.550.0.1002",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Avast": {
            "method": "blacklist",
            "engine_name": "Avast",
            "engine_version": "23.9.8494.0",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "ClamAV": {
            "method": "blacklist",
            "engine_name": "ClamAV",
            "engine_version": "1.4.3.0",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Kaspersky": {
            "method": "blacklist",
            "engine_name": "Kaspersky",
            "engine_version": "22.0.1.28",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "BitDefender": {
            "method": "blacklist",
            "engine_name": "BitDefender",
            "engine_version": "7.2",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "NANO-Antivirus": {
            "method": "blacklist",
            "engine_name": "NANO-Antivirus",
            "engine_version": "1.0.170.26895",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "SUPERAntiSpyware": {
            "method": "blacklist",
            "engine_name": "SUPERAntiSpyware",
            "engine_version": "5.6.0.1032",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Rising": {
            "method": "blacklist",
            "engine_name": "Rising",
            "engine_version": "25.0.0.28",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Emsisoft": {
            "method": "blacklist",
            "engine_name": "Emsisoft",
            "engine_version": "2024.8.0.61147",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Google": {
            "method": "blacklist",
            "engine_name": "Google",
            "engine_version": "1759881646",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "F-Secure": {
            "method": "blacklist",
            "engine_name": "F-Secure",
            "engine_version": "18.10.1547.307",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "DrWeb": {
            "method": "blacklist",
            "engine_name": "DrWeb",
            "engine_version": "7.0.72.9030",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "VIPRE": {
            "method": "blacklist",
            "engine_name": "VIPRE",
            "engine_version": "6.0.0.35",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "TrendMicro": {
            "method": "blacklist",
            "engine_name": "TrendMicro",
            "engine_version": "24.550.0.1002",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "McAfeeD": {
            "method": "blacklist",
            "engine_name": "McAfeeD",
            "engine_version": "1.2.0.10275",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "SentinelOne": {
            "method": "blacklist",
            "engine_name": "SentinelOne",
            "engine_version": "7.3.0.8",
            "engine_update": "20250827",
            "category": "undetected",
            "result": null
          },
          "CMC": {
            "method": "blacklist",
            "engine_name": "CMC",
            "engine_version": "2.4.2022.1",
            "engine_update": "20251006",
            "category": "undetected",
            "result": null
          },
          "Sophos": {
            "method": "blacklist",
            "engine_name": "Sophos",
            "engine_version": "3.2.1.0",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Ikarus": {
            "method": "blacklist",
            "engine_name": "Ikarus",
            "engine_version": "6.4.16.0",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "GData": {
            "method": "blacklist",
            "engine_name": "GData",
            "engine_version": "GD:27.42069AVA:64.29945",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Jiangmin": {
            "method": "blacklist",
            "engine_name": "Jiangmin",
            "engine_version": "16.0.100",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Varist": {
            "method": "blacklist",
            "engine_name": "Varist",
            "engine_version": "6.6.1.3",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Avira": {
            "method": "blacklist",
            "engine_name": "Avira",
            "engine_version": "8.3.3.22",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Antiy-AVL": {
            "method": "blacklist",
            "engine_name": "Antiy-AVL",
            "engine_version": "3.0",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Kingsoft": {
            "method": "blacklist",
            "engine_name": "Kingsoft",
            "engine_version": "None",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Gridinsoft": {
            "method": "blacklist",
            "engine_name": "Gridinsoft",
            "engine_version": "1.0.226.174",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Xcitium": {
            "method": "blacklist",
            "engine_name": "Xcitium",
            "engine_version": "38098",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Arcabit": {
            "method": "blacklist",
            "engine_name": "Arcabit",
            "engine_version": "2025.0.0.23",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "ViRobot": {
            "method": "blacklist",
            "engine_name": "ViRobot",
            "engine_version": "2014.3.20.0",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "ZoneAlarm": {
            "method": "blacklist",
            "engine_name": "ZoneAlarm",
            "engine_version": "6.19-108464147",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Microsoft": {
            "method": "blacklist",
            "engine_name": "Microsoft",
            "engine_version": "1.1.25080.5",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Cynet": {
            "method": "blacklist",
            "engine_name": "Cynet",
            "engine_version": "4.0.3.4",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "AhnLab-V3": {
            "method": "blacklist",
            "engine_name": "AhnLab-V3",
            "engine_version": "3.28.0.10568",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Acronis": {
            "method": "blacklist",
            "engine_name": "Acronis",
            "engine_version": "1.2.0.121",
            "engine_update": "20240328",
            "category": "undetected",
            "result": null
          },
          "VBA32": {
            "method": "blacklist",
            "engine_name": "VBA32",
            "engine_version": "5.4.0",
            "engine_update": "20251003",
            "category": "undetected",
            "result": null
          },
          "TACHYON": {
            "method": "blacklist",
            "engine_name": "TACHYON",
            "engine_version": "2025-10-08.01",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Zoner": {
            "method": "blacklist",
            "engine_name": "Zoner",
            "engine_version": "2.2.2.0",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Tencent": {
            "method": "blacklist",
            "engine_name": "Tencent",
            "engine_version": "1.0.0.1",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Yandex": {
            "method": "blacklist",
            "engine_name": "Yandex",
            "engine_version": "5.5.2.24",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "TrellixENS": {
            "method": "blacklist",
            "engine_name": "TrellixENS",
            "engine_version": "6.0.6.653",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "huorong": {
            "method": "blacklist",
            "engine_name": "huorong",
            "engine_version": "6d5e982:6d5e982:1ea32ee:1ea32ee",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "MaxSecure": {
            "method": "blacklist",
            "engine_name": "MaxSecure",
            "engine_version": "1.0.0.1",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Fortinet": {
            "method": "blacklist",
            "engine_name": "Fortinet",
            "engine_version": "7.0.30.0",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "AVG": {
            "method": "blacklist",
            "engine_name": "AVG",
            "engine_version": "23.9.8494.0",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "Panda": {
            "method": "blacklist",
            "engine_name": "Panda",
            "engine_version": "4.6.4.2",
            "engine_update": "20251007",
            "category": "undetected",
            "result": null
          },
          "alibabacloud": {
            "method": "blacklist",
            "engine_name": "alibabacloud",
            "engine_version": "2.2.0",
            "engine_update": "20250321",
            "category": "undetected",
            "result": null
          },
          "google_safebrowsing": {
            "method": "blacklist",
            "engine_name": "google_safebrowsing",
            "engine_version": "1.0",
            "engine_update": "20251008",
            "category": "undetected",
            "result": null
          },
          "Avast-Mobile": {
            "method": "blacklist",
            "engine_name": "Avast-Mobile",
            "engine_version": "251007-02",
            "engine_update": "20251007",
            "category": "type-unsupported",
            "result": null
          },
          "SymantecMobileInsight": {
            "method": "blacklist",
            "engine_name": "SymantecMobileInsight",
            "engine_version": "2.0",
            "engine_update": "20250124",
            "category": "type-unsupported",
            "result": null
          },
          "BitDefenderFalx": {
            "method": "blacklist",
            "engine_name": "BitDefenderFalx",
            "engine_version": "2.0.936",
            "engine_update": "20250416",
            "category": "type-unsupported",
            "result": null
          },
          "DeepInstinct": {
            "method": "blacklist",
            "engine_name": "DeepInstinct",
            "engine_version": "5.0.0.8",
            "engine_update": "20251007",
            "category": "type-unsupported",
            "result": null
          },
          "Elastic": {
            "method": "blacklist",
            "engine_name": "Elastic",
            "engine_version": "4.0.229",
            "engine_update": "20250929",
            "category": "type-unsupported",
            "result": null
          },
          "APEX": {
            "method": "blacklist",
            "engine_name": "APEX",
            "engine_version": "6.704",
            "engine_update": "20251007",
            "category": "type-unsupported",
            "result": null
          },
          "Paloalto": {
            "method": "blacklist",
            "engine_name": "Paloalto",
            "engine_version": "0.9.0.1003",
            "engine_update": "20251008",
            "category": "type-unsupported",
            "result": null
          },
          "Trapmine": {
            "method": "blacklist",
            "engine_name": "Trapmine",
            "engine_version": "4.0.5.0",
            "engine_update": "20250923",
            "category": "type-unsupported",
            "result": null
          },
          "Alibaba": {
            "method": "blacklist",
            "engine_name": "Alibaba",
            "engine_version": "0.3.0.5",
            "engine_update": "20190527",
            "category": "type-unsupported",
            "result": null
          },
          "Webroot": {
            "method": "blacklist",
            "engine_name": "Webroot",
            "engine_version": "1.9.0.8",
            "engine_update": "20250227",
            "category": "type-unsupported",
            "result": null
          },
          "Cylance": {
            "method": "blacklist",
            "engine_name": "Cylance",
            "engine_version": "3.0.0.0",
            "engine_update": "20251002",
            "category": "type-unsupported",
            "result": null
          },
          "tehtris": {
            "method": "blacklist",
            "engine_name": "tehtris",
            "engine_version": null,
            "engine_update": "20251008",
            "category": "type-unsupported",
            "result": null
          },
          "Trustlook": {
            "method": "blacklist",
            "engine_name": "Trustlook",
            "engine_version": "1.0",
            "engine_update": "20251008",
            "category": "type-unsupported",
            "result": null
          }
        },
        "threat_severity": {
          "version": 5,
          "threat_severity_level": "SEVERITY_NONE",
          "threat_severity_data": {},
          "last_analysis_date": "1759890300",
          "level_description": "No severity score data"
        },
        "magic": "ASCII text",
        "size": 3680,
        "last_modification_date": 1759892036,
        "type_description": "Text",
        "ssdeep": "96:pa4+/XHFCJXk3ZRpUHJMy+Tdg+TvaDP2c:g9XHm8ZRaOtTNTyP",
        "first_submission_date": 1759890259,
        "unique_sources": 1,
        "filecondis": {
          "dhash": "bef4ccaa86c28280",
          "raw_md5": "a08c2dc0a36046a2920eb37ede599c30"
        },
        "sha256": "dd9f06f323e3cff8edc24d2627b9a4c98ef06b938450c672c27d1c760742bfd9",
        "tags": [
          "text"
        ],
        "names": [
          "gradle-5.5-rc-3/subprojects/dependency-management/src/test/groovy/org/gradle/api/internal/artifacts/transform/TransformingAsyncArtifactListenerTest.groovy",
          "TransformingAsyncArtifactListenerTest.groovy"
        ],
        "type_tag": "text",
        "type_tags": [
          "text",
          "Groovy"
        ],
        "exiftool": {
          "MIMEType": "text/plain",
          "FileType": "TXT",
          "WordCount": "319",
          "LineCount": "86",
          "MIMEEncoding": "us-ascii",
          "FileTypeExtension": "txt",
          "Newlines": "Unix LF"
        },
        "total_votes": {
          "harmless": 0,
          "malicious": 0
        },
        "tlsh": "T1787123E59ACC12228343DAC7DEDFCD827779D643040610AE7C9D81B90B05D3893E7796",
        "available_tools": [],
        "downloadable": true,
        "magika": "GROOVY",
        "last_submission_date": 1759890259,
        "type_extension": "txt",
        "last_analysis_stats": {
          "malicious": 0,
          "suspicious": 0,
          "undetected": 64,
          "harmless": 0,
          "timeout": 0,
          "confirmed-timeout": 0,
          "failure": 0,
          "type-unsupported": 13
        },
        "md5": "11d83e7baead88803eb23966e15eb862",
        "times_submitted": 1,
        "crowdsourced_ai_results": [
          {
            "category": "code_insight",
            "source": "palm",
            "analysis": "This code defines a suite of unit tests for a component named `TransformingAsyncArtifactListener`. The tests verify the component's logic for managing artifact transformations within a build system context. It simulates scenarios to ensure that:\n1.  Transformations identified as \"expensive\" are added to a build operation queue for deferred execution.\n2.  Transformations identified as \"cheap\" are processed immediately if their results are readily available.\n3.  Existing or scheduled transformation results are effectively reused, preventing redundant processing.\nThe implementation uses test doubles to isolate the component and assert its behavior under specific conditions related to transformation caching and execution scheduling.",
            "verdict": "benign",
            "id": "dd9f06f323e3cff8edc24d2627b9a4c98ef06b938450c672c27d1c760742bfd9-file-palm"
          }
        ]
      },
      "context_attributes": {
        "notification_id": "23425540279",
        "origin": "hunting",
        "notification_date": 1759893861,
        "sources": [
          {
            "id": "11296052941",
            "type": "hunting_ruleset",
            "label": "playground_jumpstart_livehunts_files"
          }
        ],
        "tags": [
          "playground_jumpstart_livehunts_files",
          "leaked_documents",
          "brandmonitoring",
          "dataleak"
        ],
        "hunting_info": {
          "rule_name": "leaked_documents",
          "rule_tags": [
            "brandmonitoring",
            "dataleak"
          ],
          "source_key": "9c960419",
          "source_country": "US",
          "snippet": "74 73 2E 74 72 61 6E 73 66 6F 72 6D 0A 0A 69 6D  ts.transform..im\n70 6F 72 74 20 63 6F 6D 2E *begin_highlight*67 6F 6F 67 6C 65 2E*end_highlight*  port com.*begin_highlight*google.*end_highlight*\n*begin_highlight*63 6F 6D *end_highlight*6D 6F 6E 2E 63 6F 6C 6C 65 63 74 2E 49  *begin_highlight*com*end_highlight*mon.collect.I\n6D 6D 75 74 61 62 6C 65 4C 69 73 74 0A 69 6D 70  mmutableList.imp\n6F 72 74 20 63 6F 6D 2E *begin_highlight*67 6F 6F 67 6C 65 2E 63*end_highlight*  ort com.*begin_highlight*google.c*end_highlight*\n*begin_highlight*6F 6D *end_highlight*6D 6F 6E 2E 63 6F 6C 6C 65 63 74 2E 4D 61  *begin_highlight*om*end_highlight*mon.collect.Ma",
          "match_source": "ORIGINAL_FILE"
        }
      }
    }
  ],
  "meta": {
    "cursor": "eJwNy91ugyAYANBXQghJrxd0m8sHE_kR7mzpWgUMJlvqyB5-vT3J-fNT-gipfNutzLbrisLl5YLSz7ClBZrysDHYq077GadRxl6PNpHZwq-YUhxQxIaUDhDVc5WfpkVI5dI9_z5ORcg2HipJGVCzu2r6M2vp19uBgRwnUJdGqBuFesN8O06c9clnc386BmsirBp7Fu5u5at_7aNguvqsH84CdfadejVQXh1x2WRQrvGKR6GACNYit4bFWbPw4R-aJktu",
    "count": 100829
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false",
    "next": "https://www.virustotal.com/api/v3/ioc_stream?limit=1&descriptors_only=false&cursor=eJwNy91ugyAYANBXQghJrxd0m8sHE_kR7mzpWgUMJlvqyB5-vT3J-fNT-gipfNutzLbrisLl5YLSz7ClBZrysDHYq077GadRxl6PNpHZwq-YUhxQxIaUDhDVc5WfpkVI5dI9_z5ORcg2HipJGVCzu2r6M2vp19uBgRwnUJdGqBuFesN8O06c9clnc386BmsirBp7Fu5u5at_7aNguvqsH84CdfadejVQXh1x2WRQrvGKR6GACNYit4bFWbPw4R-aJktu"
  }
}
```

## Example 3: Descriptors_only=true and filter source_type:hunting_ruleset 
>Only limiting the responses to 5 objects for brevity. 

### Sample Request with descriptors_only=true and filter source_type:hunting_ruleset
```
curl --request GET \
     --url 'https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type%3Ahunting_ruleset' \
     --header 'accept: application/json' \
     --header 'x-apikey: <api-key>'
```

### Sample Response with descriptors_only=true and filter source_type=hunting_ruleset
```
{
  "data": [
    {
      "type": "file",
      "id": "5cc09d10367fd9af9bfd59a2ecacf3921354abeb57e1b8d60012281aa2ceed20",
      "context_attributes": {
        "notification_id": "23440467808",
        "origin": "hunting",
        "notification_date": 1759894078,
        "sources": [
          {
            "id": "20136027621",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_PotentialIntDocsContent"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_potentialintdocscontent",
          "potentialintdocscontent"
        ],
        "hunting_info": {
          "rule_name": "potentialIntDocsContent",
          "source_key": "2269ef75",
          "source_country": "US",
          "snippet": "95 57 21 08 2C 6C C1 74 99 C0 E2 1B 16 DD 86 0D  .W!.,l.t........\nA8 8C AE 28 C9 51 9A 91 AD A0 67 92 FF 06 BE *begin_highlight*49*end_highlight*  ...(.Q....g....*begin_highlight*I*end_highlight*\n*begin_highlight*4E 43 *end_highlight*D0 9C CB E3 76 C2 65 06 66 17 48 CC 08 6F  *begin_highlight*NC*end_highlight*....v.e.f.H..o",
          "match_source": "ORIGINAL_FILE"
        }
      }
    },
    {
      "type": "file",
      "id": "55d78400ee7784e6997319780e0a34cd465a383e56821e77a079294c76f6b203",
      "context_attributes": {
        "notification_id": "23438478649",
        "origin": "hunting",
        "notification_date": 1759894073,
        "sources": [
          {
            "id": "17655788362",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_PotentialIntlDocsMetadata"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_potentialintldocsmetadata",
          "potentialintdocmetadata"
        ],
        "hunting_info": {
          "rule_name": "potentialIntDocMetadata",
          "source_key": "fc9e8b82",
          "source_country": "US",
          "match_source": "ORIGINAL_FILE"
        }
      }
    },
    {
      "type": "file",
      "id": "e8f44bb180d14368e040bb25d73c75e0eee686213b5ea5a8eec7b166ff75c263",
      "context_attributes": {
        "notification_id": "23420462546",
        "origin": "hunting",
        "notification_date": 1759894055,
        "sources": [
          {
            "id": "20136027621",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_PotentialIntDocsContent"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_potentialintdocscontent",
          "potentialintdocscontent"
        ],
        "hunting_info": {
          "rule_name": "potentialIntDocsContent",
          "source_key": "b10a143f",
          "source_country": "US",
          "snippet": "43 3D 48 13 D4 5D 48 7F 04 78 69 03 CF D7 A6 21  C=H..]H.xi....!\n7D 0C F9 A5 B4 *begin_highlight*41 69 47 *end_highlight*1B F4 4C DA A0 F5 A0 16  }....*begin_highlight*AiG*end_highlight*..L.....\nFC 9A F2 0D 65 AA 6F D3 12 71 DF 1A 5A AE C5 A2  ....e.o..q..Z...\nD9 78 BA E5 33 D8 01 F9 D3 D3 8A 1C 60 1B 9C B0  .x..3.......`...\nD9 43 19 45 46 76 12 6C 59 B0 25 C0 BE DC B3 *begin_highlight*49*end_highlight*  .C.EFv.lY.%....*begin_highlight*I*end_highlight*\n*begin_highlight*4E 63 *end_highlight*E9 8E 90 32 39 2D 0D 61 1D 50 1E 67 5B 20  *begin_highlight*Nc*end_highlight*...29-.a.P.g[ ",
          "match_source": "ORIGINAL_FILE"
        }
      }
    },
    {
      "type": "file",
      "id": "8c3f8ff70e2e22d8caa80ec183ecb10553f0169fd825b0da6bff3c7dd4003ac6",
      "context_attributes": {
        "notification_id": "23423199401",
        "origin": "hunting",
        "notification_date": 1759894055,
        "sources": [
          {
            "id": "20136027621",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_PotentialIntDocsContent"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_potentialintdocscontent",
          "potentialintdocscontent"
        ],
        "hunting_info": {
          "rule_name": "potentialIntDocsContent",
          "source_key": "cafa5809",
          "source_country": "BR",
          "snippet": "20 30 29 20 7B 0A 20 20 20 20 20 20 20 20 2F 2F   0) {.        //\n20 48 61 6E 64 6C 65 20 *begin_highlight*69 6E 63 *end_highlight*6F 6D 69 6E 67   Handle *begin_highlight*inc*end_highlight*oming\n20 64 61 74 61 20 66 72 6F 6D 20 63 6F 6E 6E 65   data from conne",
          "match_source": "ORIGINAL_FILE"
        }
      }
    },
    {
      "type": "file",
      "id": "20ec79152dd3efd5d58b39d07ef016ad375af5fbfbd70d143c7acbbf688de842",
      "context_attributes": {
        "notification_id": "23425737393",
        "origin": "hunting",
        "notification_date": 1759894042,
        "sources": [
          {
            "id": "20136027621",
            "type": "hunting_ruleset",
            "label": "JumpStart_BrandMonitoring_PotentialIntDocsContent"
          }
        ],
        "tags": [
          "jumpstart_brandmonitoring_potentialintdocscontent",
          "potentialintdocscontent"
        ],
        "hunting_info": {
          "rule_name": "potentialIntDocsContent",
          "source_key": "22151978",
          "source_country": "MX",
          "snippet": "43 6B 30 7C 22 C4 41 05 71 D7 EF 35 00 6C 52 51  Ck0|\".A.q..5.lRQ\n5C D1 BE D4 6E FC 63 25 8D BD DA *begin_highlight*41 69 67 *end_highlight*1A 3C  \\...n.c%...*begin_highlight*Aig*end_highlight*.<\n89 E5 07 32 EE EC 49 E5 7F 0A 40 74 B4 51 45 30  ...2..I..@t.QE0\n4D 1D B3 CB 6D 24 CA A4 AA 60 67 38 EB 4D 26 F6  M...m$...`g8.M&.\n13 *begin_highlight*69 6E 43 *end_highlight*45 14 52 18 51 45 14 D6 E2 7B 1D FC  .*begin_highlight*inC*end_highlight*E.R.QE...{..\n7F EA D7 E8 29 D4 D8 FF 00 D5 AF D0 53 AB E9 A3  ...).......S...",
          "match_source": "ORIGINAL_FILE"
        }
      }
    }
  ],
  "meta": {
    "cursor": "eJwNy91ugjAYANBXoj8s3s7QOli-MuArhd6hbkhbSU22rBIfXq9PzsMO4fMc4q9Z42SkjEjj_pSFv2YNC5D4b_zZfOtwO9LQtb7SnQlsMnCvh-CbzNOeRQlZrqet_eqlZOjb6vVv3RDrVviEa1SQkbeJxepYiPznI1FgaQd4IjXOuSreuRrSTrneWyypMmUC9Byc4IAzG3F_GVFv6loStTUvEzk4u6hrtdhDQ2Hz3BbArJv5aDQBBDa6y2JRJJifLWZKYA==",
    "count": 97314
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type:hunting_ruleset",
    "next": "https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type%3Ahunting_ruleset&cursor=eJwNy91ugjAYANBXoj8s3s7QOli-MuArhd6hbkhbSU22rBIfXq9PzsMO4fMc4q9Z42SkjEjj_pSFv2YNC5D4b_zZfOtwO9LQtb7SnQlsMnCvh-CbzNOeRQlZrqet_eqlZOjb6vVv3RDrVviEa1SQkbeJxepYiPznI1FgaQd4IjXOuSreuRrSTrneWyypMmUC9Byc4IAzG3F_GVFv6loStTUvEzk4u6hrtdhDQ2Hz3BbArJv5aDQBBDa6y2JRJJifLWZKYA%3D%3D"
  }
}
```

## Example 4: Descriptors_only=true and filter source_type:hunting_ruleset and notification_tag:rule_name
>Only limiting the responses to 5 objects for brevity. 
>for hunting_rulesets, you use the notification_tag to filter 

### Sample Request with Descriptors_only=true and filter source_type:hunting_ruleset and notification_tag:rule_name
```
curl --request GET \
     --url 'https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type%3Ahunting_ruleset%20notification_tag%3Afuzzy_search_metamask' \
     --header 'accept: application/json' \
     --header 'x-apikey: <api-key>'
```

### Sample Request with Descriptors_only=true and filter source_type:hunting_ruleset and notification_tag:rule_name
```
{
  "data": [
    {
      "type": "url",
      "id": "696a3beef93aaf0e977693c33898e01d1bb04cfa24798a82698df05a9e8824eb",
      "context_attributes": {
        "notification_id": "23434977929",
        "origin": "hunting",
        "notification_date": 1759812849,
        "sources": [
          {
            "id": "23393991820",
            "type": "hunting_ruleset",
            "label": "fuzzy_search_metamask"
          }
        ],
        "tags": [
          "uzzy_search_metamask",
          "fuzzy_search_metamask"
        ],
        "hunting_info": {
          "rule_name": "fuzzy_search_metamask",
          "match_source": "URL_RESPONSE_BODY",
          "source_key": "0007a221"
        }
      }
    },
    {
      "type": "url",
      "id": "e52a7b6b6a55622f6fc98d40fb85a057f14ea92c29b6c301529870917ef17cba",
      "context_attributes": {
        "notification_id": "23413588419",
        "origin": "hunting",
        "notification_date": 1759812848,
        "sources": [
          {
            "id": "23393991820",
            "type": "hunting_ruleset",
            "label": "fuzzy_search_metamask"
          }
        ],
        "tags": [
          "uzzy_search_metamask",
          "fuzzy_search_metamask"
        ],
        "hunting_info": {
          "rule_name": "fuzzy_search_metamask",
          "match_source": "URL_RESPONSE_BODY",
          "source_key": "0007a221"
        }
      }
    },
    {
      "type": "url",
      "id": "6135de835a0e3960ef3b07641488aed115b1920f3035c2b07af2c7cb17190221",
      "context_attributes": {
        "notification_id": "23436709890",
        "origin": "hunting",
        "notification_date": 1759812848,
        "sources": [
          {
            "id": "23393991820",
            "type": "hunting_ruleset",
            "label": "fuzzy_search_metamask"
          }
        ],
        "tags": [
          "uzzy_search_metamask",
          "fuzzy_search_metamask"
        ],
        "hunting_info": {
          "rule_name": "fuzzy_search_metamask",
          "match_source": "URL_RESPONSE_BODY",
          "source_key": "0007a221"
        }
      }
    },
    {
      "type": "url",
      "id": "e317ac025a454da62296768bd103787cb45248b0c44523fd6ce4cb6fc9fc30d2",
      "context_attributes": {
        "notification_id": "23445921155",
        "origin": "hunting",
        "notification_date": 1759812846,
        "sources": [
          {
            "id": "23393991820",
            "type": "hunting_ruleset",
            "label": "fuzzy_search_metamask"
          }
        ],
        "tags": [
          "uzzy_search_metamask",
          "fuzzy_search_metamask"
        ],
        "hunting_info": {
          "rule_name": "fuzzy_search_metamask",
          "match_source": "URL_RESPONSE_BODY",
          "source_key": "0007a221"
        }
      }
    },
    {
      "type": "url",
      "id": "b208346b3a84875d35fa39628625667178af71ffd6eaceb8bb7a321130b41858",
      "context_attributes": {
        "notification_id": "23436816794",
        "origin": "hunting",
        "notification_date": 1759812475,
        "sources": [
          {
            "id": "23393991820",
            "type": "hunting_ruleset",
            "label": "fuzzy_search_metamask"
          }
        ],
        "tags": [
          "uzzy_search_metamask",
          "fuzzy_search_metamask"
        ],
        "hunting_info": {
          "rule_name": "fuzzy_search_metamask",
          "match_source": "URL_RESPONSE_BODY",
          "source_key": "0007a221"
        }
      }
    }
  ],
  "meta": {
    "cursor": "eJwNi9FugyAUQH8JcS57nRHW2dxLRBT1zbZbrVwMTbaUkn38fDvnJOdvGuh4ofBjtzBbKYPhoTwz-m02ukEWHtZd7FdH9xOnVru6ay3ls4WnGsg1zPE-DxJY0c1JYy_cw2yh3_97OwSlBXsapiW44nVOZX2qRPF9iBzy-AbmnClzLXB9j3jYfZ1WqGoaE3k0y4Kp3LnjUyUXqHqvDN2mD-3QQIZr6ZWtF7TwMtrPNHqRoxccjIjIm4hG-70z1fwDtv1Lhg==",
    "count": 114
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type:hunting_ruleset%20notification_tag:fuzzy_search_metamask",
    "next": "https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type%3Ahunting_ruleset+notification_tag%3Afuzzy_search_metamask&cursor=eJwNi9FugyAUQH8JcS57nRHW2dxLRBT1zbZbrVwMTbaUkn38fDvnJOdvGuh4ofBjtzBbKYPhoTwz-m02ukEWHtZd7FdH9xOnVru6ay3ls4WnGsg1zPE-DxJY0c1JYy_cw2yh3_97OwSlBXsapiW44nVOZX2qRPF9iBzy-AbmnClzLXB9j3jYfZ1WqGoaE3k0y4Kp3LnjUyUXqHqvDN2mD-3QQIZr6ZWtF7TwMtrPNHqRoxccjIjIm4hG-70z1fwDtv1Lhg%3D%3D"
  }
}
```


## Example 5: Descriptors_only=true and filter source_type:threat_profile
>Only limiting the responses to 5 objects for brevity. 

### Sample Request with Descriptors_only=true and filter source_type:threat_profile
```
curl --request GET \
     --url 'https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type%3Athreat_profile' \
     --header 'accept: application/json' \
     --header 'x-apikey: <api-key>'
```

### Sample Request with Descriptors_only=true and filter source_type:threat_profile
```
{
  "data": [
    {
      "type": "file",
      "id": "baf378121e160ab2d84ff01ff749cfa729757bd0ccc67279c45989f3b3d801aa",
      "context_attributes": {
        "notification_id": "23407791592",
        "origin": "subscriptions",
        "notification_date": 1759895727,
        "sources": [
          {
            "id": "344e7450-5eda-4eec-a6d9-cbc6562409d0",
            "type": "threat_profile",
            "label": " Energy, Finance, Gov, Healthcare Sectors"
          },
          {
            "id": "malware--448e822d-8496-5021-88cb-599062f74176",
            "type": "collection",
            "label": "BEACON"
          }
        ],
        "tags": [],
        "hunting_info": null
      }
    },
    {
      "type": "file",
      "id": "16ceeba6da20d7a41498b787b40db9f5782f0959220d78570cf1a7e82b3b2a0e",
      "context_attributes": {
        "notification_id": "23411179483",
        "origin": "subscriptions",
        "notification_date": 1759895715,
        "sources": [
          {
            "id": "344e7450-5eda-4eec-a6d9-cbc6562409d0",
            "type": "threat_profile",
            "label": " Energy, Finance, Gov, Healthcare Sectors"
          },
          {
            "id": "malware--448e822d-8496-5021-88cb-599062f74176",
            "type": "collection",
            "label": "BEACON"
          }
        ],
        "tags": [],
        "hunting_info": null
      }
    },
    {
      "type": "file",
      "id": "fafc15cc53bc188be3ebac6d00ad6588c1acaa01a343d64b70a4aa9891994e15",
      "context_attributes": {
        "notification_id": "23427983483",
        "origin": "subscriptions",
        "notification_date": 1759895713,
        "sources": [
          {
            "id": "344e7450-5eda-4eec-a6d9-cbc6562409d0",
            "type": "threat_profile",
            "label": " Energy, Finance, Gov, Healthcare Sectors"
          },
          {
            "id": "malware--448e822d-8496-5021-88cb-599062f74176",
            "type": "collection",
            "label": "BEACON"
          }
        ],
        "tags": [],
        "hunting_info": null
      }
    },
    {
      "type": "file",
      "id": "9207f033c0df69b256f35b7d05985a169391d20f6a13dfcad66de78c61a569d0",
      "context_attributes": {
        "notification_id": "23429080101",
        "origin": "subscriptions",
        "notification_date": 1759895704,
        "sources": [
          {
            "id": "344e7450-5eda-4eec-a6d9-cbc6562409d0",
            "type": "threat_profile",
            "label": " Energy, Finance, Gov, Healthcare Sectors"
          },
          {
            "id": "malware--448e822d-8496-5021-88cb-599062f74176",
            "type": "collection",
            "label": "BEACON"
          }
        ],
        "tags": [],
        "hunting_info": null
      }
    },
    {
      "type": "file",
      "id": "865d98fe8abe4bb9471e047fbfc71282efbb31c43fa239144a68ea008d07a4d7",
      "context_attributes": {
        "notification_id": "23425411067",
        "origin": "subscriptions",
        "notification_date": 1759894441,
        "sources": [
          {
            "id": "344e7450-5eda-4eec-a6d9-cbc6562409d0",
            "type": "threat_profile",
            "label": " Energy, Finance, Gov, Healthcare Sectors"
          },
          {
            "id": "malware--448e822d-8496-5021-88cb-599062f74176",
            "type": "collection",
            "label": "BEACON"
          }
        ],
        "tags": [],
        "hunting_info": null
      }
    }
  ],
  "meta": {
    "cursor": "eJwVy11vgyAUxvGvJFCT3W4B-7JwWPEAhjtbO-cONjTZojb78NOrJ7_k__zFJr13Kf-Ee25DVWXk-e1apN_zPQ2a5SlQF24uPS481ZZOrg5JtEEvpkl0Loh7kStdlK592g9fqQnJVuv_UTfZWEXz5ptiKiCcLlKVn4eZazG_aLwyg30J2x5WB8cjahZHP4B83QH2iwn2S49OGNQC0C2w98PmOCoWv_u1pwXGtZHEQNITpCeQx8lgN5j9cQf9P1WjSro=",
    "count": 3479
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type:threat_profile",
    "next": "https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type%3Athreat_profile&cursor=eJwVy11vgyAUxvGvJFCT3W4B-7JwWPEAhjtbO-cONjTZojb78NOrJ7_k__zFJr13Kf-Ee25DVWXk-e1apN_zPQ2a5SlQF24uPS481ZZOrg5JtEEvpkl0Loh7kStdlK592g9fqQnJVuv_UTfZWEXz5ptiKiCcLlKVn4eZazG_aLwyg30J2x5WB8cjahZHP4B83QH2iwn2S49OGNQC0C2w98PmOCoWv_u1pwXGtZHEQNITpCeQx8lgN5j9cQf9P1WjSro%3D"
  }
}
```

## Example 6: Descriptors_only=true and filter source_type:threat_profile and source_id:id
>Only limiting the responses to 5 objects for brevity. 
> For threat profiles, it uses the source_id to filter

### Sample Request with Descriptors_only=true and filter source_type:threat_profile and source_id:id
```
curl --request GET \
     --url 'https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type%3Athreat_profile%20source_id%3A70ab5b83f8b542afab180b57f06b55ab' \
     --header 'accept: application/json' \
     --header 'x-apikey: <api-key>'
```

### Sample Request with Descriptors_only=true and filter source_type:threat_profile and source_id:id
```
{
  "data": [
    {
      "type": "url",
      "id": "https://api.tekpulsecoincatapp.monster/?zrs=514608fc5d36fe128fd24dd8c43497ab",
      "context_attributes": {
        "notification_id": "23414702258",
        "origin": "subscriptions",
        "notification_date": 1759480396,
        "sources": [
          {
            "id": "70ab5b83f8b542afab180b57f06b55ab",
            "type": "threat_profile",
            "label": "Dom_Singapore_Healthcare"
          },
          {
            "id": "malware--0b1985e1-c57a-54b4-aa4a-d318e69e3644",
            "type": "collection",
            "label": "CURLYFENCE"
          }
        ],
        "tags": [],
        "hunting_info": null
      }
    },
    {
      "type": "url",
      "id": "https://api.tekpulsecoincatapp.monster/?zrs=f5041f11c5c72527b1a6592c65ff5417",
      "context_attributes": {
        "notification_id": "23426381387",
        "origin": "subscriptions",
        "notification_date": 1759480388,
        "sources": [
          {
            "id": "70ab5b83f8b542afab180b57f06b55ab",
            "type": "threat_profile",
            "label": "Dom_Singapore_Healthcare"
          },
          {
            "id": "malware--0b1985e1-c57a-54b4-aa4a-d318e69e3644",
            "type": "collection",
            "label": "CURLYFENCE"
          }
        ],
        "tags": [],
        "hunting_info": null
      }
    },
    {
      "type": "url",
      "id": "https://mega.nz/file/1l8wBQhA",
      "context_attributes": {
        "notification_id": "23436328344",
        "origin": "subscriptions",
        "notification_date": 1759480361,
        "sources": [
          {
            "id": "70ab5b83f8b542afab180b57f06b55ab",
            "type": "threat_profile",
            "label": "Dom_Singapore_Healthcare"
          },
          {
            "id": "malware--0b1985e1-c57a-54b4-aa4a-d318e69e3644",
            "type": "collection",
            "label": "CURLYFENCE"
          }
        ],
        "tags": [],
        "hunting_info": null
      }
    },
    {
      "type": "url",
      "id": "https://gfs204n175.userstorage.mega.co.nz/dl/eEAcf3Ks_sDsagdzmQRayl1lN8kcxOul2oBKX4PNrc0UpGhZsVyofHJ6O0we0dURjrMj4SdzBRdDlylVSOUxjdPJUyPToxHEbtgw8hYOhaSu102thu97G-P9WdH_lQ",
      "context_attributes": {
        "notification_id": "23403646552",
        "origin": "subscriptions",
        "notification_date": 1759480356,
        "sources": [
          {
            "id": "70ab5b83f8b542afab180b57f06b55ab",
            "type": "threat_profile",
            "label": "Dom_Singapore_Healthcare"
          },
          {
            "id": "malware--0b1985e1-c57a-54b4-aa4a-d318e69e3644",
            "type": "collection",
            "label": "CURLYFENCE"
          }
        ],
        "tags": [],
        "hunting_info": null
      }
    },
    {
      "type": "url",
      "id": "https://api.pagelivekeylearnbestz.com/?zrs=39e29ced6014c056c8ac8df879ab4b44",
      "context_attributes": {
        "notification_id": "23426275868",
        "origin": "subscriptions",
        "notification_date": 1759480350,
        "sources": [
          {
            "id": "70ab5b83f8b542afab180b57f06b55ab",
            "type": "threat_profile",
            "label": "Dom_Singapore_Healthcare"
          },
          {
            "id": "malware--0b1985e1-c57a-54b4-aa4a-d318e69e3644",
            "type": "collection",
            "label": "CURLYFENCE"
          }
        ],
        "tags": [],
        "hunting_info": null
      }
    }
  ],
  "meta": {
    "cursor": "eJwVy9FugjAUgOFXgiLLvBxpu4FpO0rh0N6hbog9mJq4IM0eXr368138_67H3RHDDS5hAM6DIaE4JPhXX3ASaVjAH-GnxeueYKN91TaA2QBiVT36OvGkywIXSd4OsfjWjL8Z1K__2vRBaeZXA-Es2i0Do6s9Zfnv152I7P4uzCFVZszlmSWqfxq6k4wic8BRmo9VzHJ2Mz_Z2KGi40Z-Su-gXhRlRAKfHC1zG8vVzWXqqH9WLNYw4qCbbCzQQoV2fAB0oku-",
    "count": 1000
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type:threat_profile%20source_id:70ab5b83f8b542afab180b57f06b55ab",
    "next": "https://www.virustotal.com/api/v3/ioc_stream?limit=5&descriptors_only=true&filter=source_type%3Athreat_profile+source_id%3A70ab5b83f8b542afab180b57f06b55ab&cursor=eJwVy9FugjAUgOFXgiLLvBxpu4FpO0rh0N6hbog9mJq4IM0eXr368138_67H3RHDDS5hAM6DIaE4JPhXX3ASaVjAH-GnxeueYKN91TaA2QBiVT36OvGkywIXSd4OsfjWjL8Z1K__2vRBaeZXA-Es2i0Do6s9Zfnv152I7P4uzCFVZszlmSWqfxq6k4wic8BRmo9VzHJ2Mz_Z2KGi40Z-Su-gXhRlRAKfHC1zG8vVzWXqqH9WLNYw4qCbbCzQQoV2fAB0oku-"
  }
}
```