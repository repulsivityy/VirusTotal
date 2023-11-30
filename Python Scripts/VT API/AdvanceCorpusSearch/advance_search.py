import os
from pprint import pprint
import urllib
import requests

#QUERY = 'entity:file submitter:au fs:2023-11-01+ fs:2023-11-14-'
#QUERY = 'entity:ip country:au last_modification_date:2023-11-01+ last_modification_date:2023-11-14-'
LIMIT = '10' #Max is 300 results
#ORDER = 'last_submission_date' #see below for order. Default is last_submission for files and url, and last_modification for domains and IP

def advanced_search(query):
  url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&limit={LIMIT}&descriptors_only=false'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

res = advanced_search(QUERY)
pprint(res)


