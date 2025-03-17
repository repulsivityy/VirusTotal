####
# Creates a python file to
# Take the input of a VirusTotal Collection 
# Run the Advance Corpus Search
# PATCH the outputs into a Collection via https://virustotal.com/reference/collections-update

import json
import os
from pprint import pprint
import urllib
import requests
import time

################
# variables
################
#FS_DATE = input("Enter First Seen Start Date (eg 2023-12-01+): ")
#LS_DATE = input("Enter First Seen End Date (eg 2023-12-31-): ")
#SUBMITTER = input("Enter ISO of Country (eg SG): ")
#LIMIT = '300'
#FILE_DETECT = 'entity:file submitter:'+ SUBMITTER +' fs:'+ FS_DATE +' fs:'+ LS_DATE +' p:1+'
#COLLECTION_ID = input("Enter Collection ID: ")
COLLECTION_ID = 'bc2804474cfd92eb4c599112df0ff0f8ebe8b32dd1f9027bd5c0f6855ece8f36'
VT_APIKEY = os.environ['GTI_APIKEY']
firstseen = "2025-02-7+"
lastseen = "2025-02-14-"
#firstseen = input("Enter First Seen Start Date (eg 2023-12-01+):")
#lastseen = input("Enter First Seen End Date (eg 2023-12-31-):")
LIMIT = '300'
#FILE_DETECT = 'entity:file submitter:au fs:'+ firstseen +' fs:'+ lastseen +' p:1+'
FILE_DETECT = 'entity:file malware_config:lumma fs:7d+'

################
# advance search
################
def file(query): 
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': VT_APIKEY}
    hashes = []  # Initialize an empty list to store hashes

    while True:  # trying out 
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        data = res.json()

        # Append current page's data to the list
        if "data" in data:
            for item in data["data"]:
                if "attributes" in item and "sha256" in item["attributes"]:
                    hashes.append(item["attributes"]["sha256"])

        # Check for pagination
        if "links" in data and "next" in data["links"]:
            url = data["links"]["next"]
        else:
            break  # Exit loop if no next page
        print(f"Found {len(hashes)} hashes so far...")

    return hashes

def update_collection(collection, hashes):
    url = f'https://www.virustotal.com/api/v3/collections/{COLLECTION_ID}'
    headers = {'Accept': 'application/json', "content-type": "application/json", 'x-apikey': VT_APIKEY}
    
    payload = {
	    "data": {
		    #"attributes": {
			#    "name": COLLECTION_NAME,
			#    "description": COLLECTION_DESCRIPTION
	    	#},
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
    res = requests.patch(url, json=payload, headers=headers)
    res.raise_for_status()
    print("\nCollection Updated Successfully\n")
    return res.json()

try:
    hashes = file(FILE_DETECT)
    vt_col_link = "https://www.virustotal.com/gui/collection/" # Link to VT collection

    if "data" in hashes:
        for item in hashes["data"]:
           if "attributes" in item and "sha256" in item["attributes"]:
                hashes.append(item["attributes"]["sha256"])

    print("\n#########################")
    print("Results:")
    print("#########################")
    print("This is the VirusTotal search term:\033[92m", FILE_DETECT, "\033[0;0m") 
    pprint(f"Total Number of Hashes Updated Into Collection: {len(hashes)}") #Print number of hashes
    print("Collection ID:", COLLECTION_ID) # Print the Collection ID
    print("Link to Collection:", vt_col_link + COLLECTION_ID) # Print link to collection
    
    # Check if hashes list is empty
    if not hashes:
        print("No hashes found, skipping collection creation.")
    else:
       print("Collection Updated")
       #collection_details = json.loads(json_response)

############
# error handling
############
except requests.RequestException as e:
    print(f"Request error: {e}")
except (KeyError, json.JSONDecodeError) as e:  # Catch more specific errors
    print(f"Error processing json data: {e}")
except Exception as e:
    print(f"An error occurred: {e}")