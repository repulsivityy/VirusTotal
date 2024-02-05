import os
from pprint import pprint
import urllib
import requests

QUERY = 'entity:file submitter:au fs:2023-11-22+ fs:2023-11-24-'
LIMIT = '10' #Max is 300 results

def advanced_search(query):
  url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&limit={LIMIT}&descriptors_only=false'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

res = advanced_search(QUERY)
pprint(res)


