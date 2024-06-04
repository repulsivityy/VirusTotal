################
# Python Script to 
# 1. create a collection (done)
# 2. add in indicators from an advance search (partial - to work on pagination next)
# 3. get the top 3 malware families, and top 3 threat categories (done)
# 4. update results from #3 to a google sheets (todo)
#
# author: VirusTotal // dominicchua@google.com
# currently WIP
# USE AT YOUR OWN RISK
################

import json
import os
from pprint import pprint
import urllib
import requests
import time

################
# variables
################
firstseen = "2024-05-01+"
lastseen = "2024-05-31-"
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

    return hashes

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
    res = requests.post(url, json=payload, headers=headers)
    res.raise_for_status()
    print("\nCollection Create Successfully\n")
    return res.json()

#######################
#get collection details
#######################
def get_collection(id):
    url = f"https://www.virustotal.com/api/v3/collections/{id}"
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    #print(res.text)
    return json.dumps(res.json())

#######################
#get top threats 
# malware families, threat categories, c2 url, file types, collections
# current giving output errors - to solve
#######################
def print_top_trends(json_response):
    # Parse JSON
    data = json.loads(json_response)

    # Extract top 3 malware families
    malware_families = data['data']['attributes']['aggregations']['files']['malware_config_family_name'][:3]

    # Extract top 3 threat categories
    threat_categories = data['data']['attributes']['aggregations']['files']['popular_threat_category'][:3]

    # Extract top 3 malware config C2 URLs
    #c2_urls = data['data']['attributes']['aggregations']['files']['malware_config_c2_url'][:3]

    # Extract top 3 malware config C2 URLs
    file_types = data['data']['attributes']['aggregations']['files']['file_types'][:3]

    # Print out relevant matrics
    print("\n#########################")
    print("Printing top trends")
    print("#########################")
    # Print top 3 popular malware families
    print("\nTop 3 Malware Families:")
    for mal in malware_families:
        print(f"{mal['value']}: {mal['count']}")

    # Print top 3 threat categories
    print("\nTop 3 Threat Categories:")
    for category in threat_categories:
        print(f"{category['value']}: {category['count']}")

    # Print top 3 C2 URLs
    #print("\nTop 3 Malware Config C2 URLs:")
    #for c2 in c2_urls:
    #    print(f"{c2['value']}: {c2['count']}")

    # Print top 3 File Types
    print("\nTop 3 Malware File Types:")
    for file in file_types:
        print(f"{file['value']}: {file['count']}")

#######################
#delete collection
#######################
def delete_collection(id):
    while True:
        print("\n#########################")
        user_input = input("\nDo you want to delete the collection (Y/N):")
        if user_input.lower() == 'y':
            url = f"https://www.virustotal.com/api/v3/collections/{id}"
            headers = {'Accept': 'application/json', "content-type": "application/json", 'x-apikey': os.environ['VT_APIKEY']}
            res = requests.delete(url, headers=headers)
            res.raise_for_status()
            print(res.text)
            print("\nDeleting Collection.")
            break
        elif user_input.lower() == 'n':
            print("Collection not deleted. Link to Collection:", vt_col_link + id)
            return
        else:
            print("Invalid input. Please enter 'y' or 'n'.")


#######################
#main
#######################
try:
    hashes = file(FILE_DETECT)
    vt_col_link = "https://www.virustotal.com/gui/collection/" # Link to VT collection

# Use only if descripters_only=false 
    if "data" in hashes:
        for item in hashes["data"]:
           if "attributes" in item and "sha256" in item["attributes"]:
                hashes.append(item["attributes"]["sha256"])

# Use only when descriptors_only=true
#    if "data" in res:
#        for item in res["data"]:
#                hashes.append(item["id"])
    print("This is the VirusTotal search term: ", FILE_DETECT)
    pprint(f"Total Number of Hashes: {len(hashes)}") #Print number of hashes
    collection_link = create_collection(COLLECTION_NAME, hashes)  # Get JSON response
    collection_id = collection_link["data"]["id"]  # Extract Collection ID from JSON response
    print("Collection ID:", collection_id) # Print the Collection ID
    print("Link to Collection:", vt_col_link + collection_id) # Print link to collection
    
    # Check if hashes list is empty
    if not hashes:
        print("No hashes found, skipping collection creation.")
    else:
        # Retry mechanism
        max_retries = 3
        retry_count = 0
        while retry_count < max_retries:
            json_response = get_collection(collection_id)
            collection_details = json.loads(json_response)
            if "files" in collection_details.get("data", {}).get("attributes", {}).get("aggregations", {}):
                print("Collection processing complete.")
                print_top_trends(json_response)
                break  # Exit loop if 'files' key is found
            else:
                print("Collection still processing. Retrying in 30 seconds...")
                time.sleep(15)
                retry_count += 1
                print("Retry count:", retry_count)

        if retry_count == max_retries:
            print("Maximum retries reached. Collection may be empty or processing has not completed.")

    delete_collection(collection_id) # cleanup collection during testing 

############
#error handling
############
except requests.RequestException as e:
    print(f"Request error: {e}")
except Exception as e:
    print(f"An error occurred: {e}")