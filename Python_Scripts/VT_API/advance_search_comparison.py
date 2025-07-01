##############
# VirusTotal Intelligence Search to IOC Collection
#
# This script performs multiple VirusTotal Intelligence searches for different
# entity types (files, URLs, domains, IPs) and compiles the results into a
# single IOC Collection for easy tracking and management.
##############

import json
import os
from pprint import pprint
import urllib.parse
import requests
import time
import re

class color:
    red = '\033[91m'
    darkcyan = '\033[36m'
    green = '\033[92m'
    blue = '\033[94m'
    end = '\033[0m'

# --- Configuration ---
# The script uses GTI_APIKEY, but you can change it to VT_APIKEY if you prefer.
API_KEY = os.environ.get('GTI_APIKEY')
if not API_KEY:
    raise ValueError("GTI_APIKEY environment variable not set.")

BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {'Accept': 'application/json', 'x-apikey': API_KEY, 'x-tool': 'gti-advance-search'}

def search_intelligence(query):
    """
    Performs a VirusTotal Intelligence search, handles pagination, and returns a list of IOCs.
    """
    iocs = []
    search_url = f"{BASE_URL}/intelligence/search"
    # Use descriptors_only=True for efficiency as we only need the ID and type.
    # The API page limit is 300.
    params = {'query': query, 'limit': 300, 'descriptors_only': True}
    
    page_count = 0
    has_printed_total = False

    while True:
        try:
            # Make the request first
            res = requests.get(search_url, headers=HEADERS, params=params)
            res.raise_for_status()
            data = res.json()

            # On the first successful request, print the total hits
            if not has_printed_total:
                total_hits = data.get('meta', {}).get('total_hits', 0)
                print(f"  {color.darkcyan}Total hits found: {total_hits}{color.end}")
                if total_hits == 0:
                    break  # Exit if there's nothing to fetch
                print(f"  Now fetching all available IOCs (300 per page)...")
                has_printed_total = True

            page_count += 1
            print(f"  Fetched page {page_count} ({len(data.get('data', []))} items)...")

            # Process the data from the current page
            if "data" in data:
                for item in data["data"]:
                    iocs.append({'type': item.get('type'), 'id': item.get('id')})

            # Check for the next page
            cursor = data.get('meta', {}).get('cursor')
            if cursor:
                params['cursor'] = cursor
            else:
                break  # No more pages, exit the loop
        except requests.HTTPError as e:
            print(f"{color.red}  HTTP Error during search: {e.response.status_code} - {e.response.text}{color.end}")
            break
        except Exception as e:
            print(f"{color.red}  An unexpected error occurred during search: {e}{color.end}")
            break

    return iocs

def create_ioc_collection(name, description, iocs):
    """
    Creates an IOC collection on VirusTotal with the given IOCs.
    """
    # Group IOCs by type
    grouped_iocs = {
        'files': [],
        'urls': [],
        'domains': [],
        'ip_addresses': []
    }
    
    type_mapping = {
        'file': 'files',
        'url': 'urls',
        'domain': 'domains',
        'ip_address': 'ip_addresses'
    }

    for ioc in iocs:
        ioc_type_singular = ioc.get('type')
        ioc_id = ioc.get('id')
        
        if ioc_type_singular and ioc_id:
            plural_type = type_mapping.get(ioc_type_singular)
            if plural_type:
                # The API expects a list of {'type': '...', 'id': '...'} objects
                # The type here is the singular form.
                grouped_iocs[plural_type].append({'type': ioc_type_singular, 'id': ioc_id})

    # Build relationships dictionary, only including types with IOCs
    relationships = {}
    for plural_type, ioc_list in grouped_iocs.items():
        if ioc_list:
            relationships[plural_type] = {'data': ioc_list}

    if not relationships:
        print("No valid IOCs to add to the collection.")
        return None

    # Build the final payload
    payload = {
        "data": {
            "type": "collection",
            "attributes": {
                "name": name,
                "description": description
            },
            "relationships": relationships
        }
    }

    collection_url = f"{BASE_URL}/collections"
    res = requests.post(collection_url, headers=HEADERS, json=payload)
    res.raise_for_status()
    return res.json()

def main():
    # --- Get User Query ---
    user_query = input("Enter your VTI search query (must start with 'entity:file', 'entity:url', 'entity:domain', or 'entity:ip'):\n> ")

    # --- Validate Query ---
    if not re.match(r"^\s*entity:(file|url|domain|ip)\b", user_query.strip()):
        print(f"{color.red}Invalid query format. The query must start with 'entity:file', 'entity:url', 'entity:domain', or 'entity:ip'.{color.end}")
        return

    # --- Perform Search ---
    print(f"\n{color.blue}--- Starting IOC Search ---{color.end}")
    print(f"  Query: {user_query}")
    
    all_iocs = search_intelligence(user_query)

    if not all_iocs:
        print(f"\n{color.red}No IOCs found for the given query. Exiting.{color.end}")
        return

    # --- Create Collection ---
    print(f"\n{color.blue}--- Found {len(all_iocs)} IOCs to add to collection ---{color.end}")

    # Generate a default name based on the query
    default_name = f"Collection for query: {user_query[:50]}..." if len(user_query) > 50 else f"Collection for query: {user_query}"
    collection_name = input(f"Enter collection name (press Enter for default: '{default_name}'): ") or default_name
    
    collection_desc = input(f"Enter collection description (press Enter to use the query as description):\n> ") or f"IOCs found using the VTI query:\n\n{user_query}"

    print(f"\nCreating collection: '{collection_name}'")

    try:
        collection_result = create_ioc_collection(collection_name, collection_desc, all_iocs)
        collection_id = collection_result.get("data", {}).get("id")
        
        if collection_id:
            collection_link = f"https://www.virustotal.com/gui/collection/{collection_id}"
            print(f"\n{color.green}--- Collection Created Successfully! ---{color.end}")
            print(f"Name: {collection_name}")
            print(f"ID: {collection_id}")
            print(f"Link: {color.blue}{collection_link}{color.end}")
        else:
            print(f"\n{color.red}--- Failed to create collection ---{color.end}")
            pprint(collection_result)
            
    except requests.HTTPError as e:
        print(f"{color.red}\n--- Error creating collection ---{color.end}")
        print(f"Status Code: {e.response.status_code}")
        try:
            pprint(e.response.json())
        except json.JSONDecodeError:
            print(e.response.text)

if __name__ == "__main__":
    main()
