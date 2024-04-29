######
# Python Script to 
# 1. create a collection
# 2. add in indicators from an advance search
# author: dominicchua@google.com
# currently WIP
######

import json
import os
from pprint import pprint
import urllib
import requests


# variables
firstseen = "2024-04-22+"
lastseen = "2024-04-24-"
#firstseen = input("Enter First Seen Start Date (eg 2023-12-01+):")
#lastseen = input("Enter First Seen End Date (eg 2023-12-31-):")
LIMIT = '10'
FILE_DETECT = 'entity:file submitter:au fs:'+ firstseen +' fs:'+ lastseen +' p:1+'
COLLECTION_NAME = 'Test Collection' #name of collection to be used

def file(query): 
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    return res.json()


#create a collection
"""
def create_collection(collection):
    url = f"https://www.virustotal.com/api/v3/collections"
    headers = {'Accept': 'application/json', "content-type": "application/json", 'x-apikey': os.environ['VT_APIKEY']}
    
    payload = {
	    "data": {
		    "attributes": {
			    "name": COLLECTION_NAME,
			    "description": "This is how to create a new collection via API."
	    	},
		    "relationships": {
			    "files": {
				    "data": [
					    {
						    "type": "file",
						    "id": "ecc0f2aa29b102bf8d67b7d7173e8698c0341ddfdf9757be17595460fbf1791a"
					    }
				    ]
			    }
		    },
		    "type": "collection"
	    }
    }
    response = requests.post(url, json=payload, headers=headers)
    print(response.text)
"""

#create_collection(COLLECTION_NAME)
res = file(FILE_DETECT)
pprint(res)