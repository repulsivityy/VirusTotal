#####################################
# Purpose: To automatically pull the latest categorised threat list
# Code is provided as best effort. Use at your own risk
# VirusTotal/GTI // dominicchua@google.com
#
# requirements:
# - Google Threat Intelligence API Key
# - GTI Standard / Enterprise / Enterprise + license
#
# Usage
# - update QUERY to the threat list you require
# 
# Optional: 
# 1. if all results are needed, uncomment the LIMIT var, and append "/latest?limit={LIMIT}" to the url
# 2. by deafult, response format is JSON, update format to (json, csv, stix, misp), and append to "/latest?format={FORMAT}"
# 3. by default, it returns all entities where applicable. If only one entity is required, (file, url, ip_address, domain), append "/latest?type={TYPE}"
#
# Example: 
# https://www.virustotal.com/api/v3/threat_lists/{query}/latest?limit={LIMIT}&format={FORMAT}&type={TYPE}
######################################
 
import os
import requests
from pprint import pprint

QUERY = "phishing"
X_TOOL = 'threat_list'
#LIMIT = "2"
#&FORMAT = "stix"
#TYPE = 'url'

def get_threat_list(query):
    url = f'https://www.virustotal.com/api/v3/threat_lists/{query}/latest'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['GTI_APIKEY'], 'x-tool': X_TOOL }
    res = requests.get(url, headers=headers)
    try:
        res = requests.get(url, headers=headers)
        res.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        return res.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching threat list '{query}': {e}")
        return None
    except KeyError:
        print(f"Error: GTI_APIKEY environment variable not set.")
        return None

res = get_threat_list(QUERY)
pprint(res)