import os
import requests

url = "https://www.virustotal.com/api/v3/dtm/monitors"

payload = { 
    "doc_condition": {
        "operator": "must_equal",
        "topic": "doc_type",
        "match": [
            {
                "operator": "must_equal",
                "topic": "doc_type",
                "match": [
                  "forum_post",
                  "shop_listing"
                ],
                "labels": {
                  "condition_type": "system",
                  "editable": "true"
                }
            },
            {
                "operator": "must_equal",
                "topic": "group_brand",
                "match": ["google", "谷歌"],
                "labels": {
                  "condition_type": "user",
                  "editable": "true"
                }
            }
        ]
    },
    "description": "test_google_DDW_monitor",
    "enabled": True,
    "name": "google_DDW_monitor",
}
headers = {
    "accept": "application/json",
    "x-apikey": os.environ["GTI_APIKEY"],
    "content-type": "application/json"
}

response = requests.post(url, json=payload, headers=headers)

print(response.text)