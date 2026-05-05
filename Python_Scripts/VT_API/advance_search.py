import os
from pprint import pprint
import urllib
import requests

QUERY = 'entity:domain last_modification_date:1d+ p:20+'
LIMIT = '300' #Max is 300 results per page

def advanced_search(query):
  url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&limit={LIMIT}&descriptors_only=true'
  headers = {'Accept': 'application/json', 'x-apikey': os.environ['GTI_APIKEY']}
  res = requests.get(url, headers=headers)
  res.raise_for_status()
  return res.json()

res = advanced_search(QUERY)
pprint(res)