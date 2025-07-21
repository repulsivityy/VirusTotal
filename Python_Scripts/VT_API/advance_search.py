import os
from pprint import pprint
import urllib
import requests

QUERY = 'entity:file type:apk p:10+ have:threat_actor'
LIMIT = '2' #Max is 300 results per page

def advanced_search(query):
  url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&limit={LIMIT}&descriptors_only=false'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['GTI_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

res = advanced_search(QUERY)
pprint(res)