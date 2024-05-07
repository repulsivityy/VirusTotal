######
# Python Script to 
# 1. create a collection (done)
# 2. add in indicators from an advance search (partial)
# 3. get the top 3 malware families, and top 3 threat categories
# 4. update results from #3 to a google sheets
# author: dominicchua@google.com
# currently WIP
######

import json
import os
from pprint import pprint
import urllib
import requests
import time


# variables
firstseen = "2024-04-15+"
lastseen = "2024-04-30-"
#firstseen = input("Enter First Seen Start Date (eg 2023-12-01+):")
#lastseen = input("Enter First Seen End Date (eg 2023-12-31-):")
LIMIT = '300'
FILE_DETECT = 'entity:file submitter:au fs:'+ firstseen +' fs:'+ lastseen +' p:1+'
#COLLECTION_NAME = input("Enter Collection Name (eg 'Test Collection'): ") #name of collection to be used
#COLLECTION_DESCRIPTION = input("Enter Collection Description (eg 'For Trends in past 7 days'): ") #description of collection to be used
COLLECTION_NAME = "test collection"
COLLECTION_DESCRIPTION = "test description"

################
#advance search
################
def file(query): 
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    return res.json()

################
#create and update collection
################
def create_collection(collection, hashes):
    url = f"https://www.virustotal.com/api/v3/collections"
    headers = {'Accept': 'application/json', "content-type": "application/json", 'x-apikey': os.environ['VT_APIKEY']}
    
    payload = {
	    "data": {
		    "attributes": {
			    "name": COLLECTION_NAME,
			    "description": COLLECTION_DESCRIPTION
	    	},
		    "relationships": {
			    "files": {
				    "data": [
					    {
						    "type": "file",
						    "id": h
					    } for h in hashes
				    ]
			    }
		    },
		    "type": "collection"
	    }
    }
    response = requests.post(url, json=payload, headers=headers)
    print("\nCollection Create Successfully\n")
    return response.json()

#######################
#get collection details
#######################
def get_collection(id):
    url = f"https://www.virustotal.com/api/v3/collections/{id}"
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    response = requests.get(url, headers=headers) 
    print(response.text)
    #return res.json()

#######################
#delete collection
#######################
def delete_collection(id):
    url = f"https://www.virustotal.com/api/v3/collections/{id}"
    headers = {'Accept': 'application/json', "content-type": "application/json", 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.delete(url, headers=headers)
    print(res.text)


#######################
#main
#######################
try:
    res = file(FILE_DETECT)
    hashes = []  # Initialize an empty list to store hashes
    vt_col_link = "https://www.virustotal.com/gui/collection/" # Link to VT collection

    if "data" in res:
        for item in res["data"]:
            if "attributes" in item and "sha256" in item["attributes"]:
                hashes.append(item["attributes"]["sha256"])

    pprint(f"Total Number of Hashes: {len(hashes)}") #Print number of hashes
    collection_link = create_collection(COLLECTION_NAME, hashes)  # Get JSON response
    collection_id = collection_link["data"]["id"]  # Extract Collection ID from JSON response
    print("Collection ID:", collection_id) # Print the Collection ID
    print("Link to Collection:", vt_col_link + collection_id) # Print link to collection
    print("\nWaiting for 10 seconds...") #wait needed for commmonalities to be computed
    time.sleep(10)
    get_collection(collection_id) # Get collection details
    #delete_collection(collection_id) # cleanup collection during testing 

############
#error handling
############
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
except requests.exceptions.HTTPError as e:
    print(f"HTTP error occurred: {e}")
except Exception as e:
    print(f"An error occurred: {e}")