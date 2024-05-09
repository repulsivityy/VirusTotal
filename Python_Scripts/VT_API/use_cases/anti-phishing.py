#############
# Usage: 
# 1. Load VT API Key as an environment variable (VT_APIKEY) 
# 2. Update the query based on VirusTotal's search terms
# 3. Results returned in JSON format
# Code is provided as best effort. Use at your own risk
# VirusTotal // dominicchua@google.com
#############

import os
from pprint import pprint
import urllib
import requests

QUERY = 'entity:url (content:"google" or title:"google login") not parent_domain:google.com ls:30d+ response_code:200'
LIMIT = '1' #Max is 300 results

def advanced_search(query):
  url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&limit={LIMIT}&descriptors_only=false'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

res = advanced_search(QUERY)
pprint(res)
