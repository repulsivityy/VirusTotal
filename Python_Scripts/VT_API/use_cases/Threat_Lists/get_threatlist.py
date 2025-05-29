#####################################
# Purpose: To automatically download 
# Others: learning argparse, so using that. if planning to run automatically, remove the LIMITS and run it every hour. Sample code under "get_threatlist_auto.py"
# Code is provided as best effort. Use at your own risk
# VirusTotal/GTI // dominicchua@google.com
#
# requirements:
# - Google Threat Intelligence API Key
# - GTI Standard / Enterprise / Enterprise + license
#
# Usage
# get_threatlist.py -THREATS <available_lists> -LIMIT <# of results return>
#####################################
 
import os
from pprint import pprint
import requests
import argparse

DEFAULT_LIMIT = 10
X_TOOL = 'threat_list'
AVAILABLE_LISTS = ["ransomware", "malicious-network-infrastructure", "malware", "threat-actor", "trending", "mobile", "osx", "linux", "iot", "cryptominer", "phishing", "first-stage-delivery-vectors", "vulnerability-weaponization", "infostealer"]

THREAT_LIST_DESCRIPTIONS = {
    "ransomware": "Malware IOCs categorized as ransomware by VT engines or Mandiant intelligence.",
    "malicious-network-infrastructure": "Network infrastructure IOCs extracted from malware its contacted network IOCs.",
    "malware": "IOCs categorized as malware by the Mandiant intelligence.",
    "threat-actor": "Malware IOCs associated with some Threat Actors.",
    "trending": "Daily malware top IOCs in GTI.",
    "mobile": "IOS and Android malware.",
    "osx": "OS X malware.",
    "linux": "Linux malware.",
    "iot": "Linux malware categorized as IoT by the VT engines.",
    "cryptominer": "Malware IOCs categorized as miners by the VT engines.",
    "phishing": "Malware IOCs categorized as phishing by the VT engines.",
    "first-stage-delivery-vectors": "Malware IOCs found attached in emails and its embedded urls. Also ITW urls that have seen these IOCs.",
    "vulnerability-weaponization": "Malware IOCs associated with vulnerabilities.", 
    "infostealer": "IOCs categorized as stealers by the VT engines or Mandiant Intelligence."
}

def display_threat_lists():
    """Prints the available threat lists with aligned descriptions."""
    try:
        max_name_length = max(len(name) for name in THREAT_LIST_DESCRIPTIONS.keys())
    except ValueError: # Handle case where the dictionary might be empty
        max_name_length = 0

    for name, description in THREAT_LIST_DESCRIPTIONS.items():
        padding = ' ' * (max_name_length - len(name) + 2) # Add 2 extra spaces for separation
        print(f"- {name}{padding}### {description}")

def get_threat_list(query, limit):
    url = f'https://www.virustotal.com/api/v3/threat_lists/{query}/latest?limit={limit}'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['GTI_APIKEY'], 'x-tool': X_TOOL }
    try:
        res = requests.get(url, headers=headers)
        res.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        return res.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching threat list '{query}': {e}")
        return None
    except KeyError:
        print(f"Error: GTI_APIKEY environment variable not set.")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Example usage: get_threatlist.py -THREAT phishing -LIMIT 10")
    parser.add_argument("-LIST", action="store_true", help="Display the available threat lists.")
    parser.add_argument("-THREAT", metavar='', help="The name of the threat list to fetch (e.g., phishing).")
    parser.add_argument("-LIMIT", metavar='', type=int, default=DEFAULT_LIMIT, help=f"The number of results to fetch (default: {DEFAULT_LIMIT}). ")
    
    args = parser.parse_args()

    if args.LIST:
        display_threat_lists()
    elif args.THREAT:
        if args.THREAT in AVAILABLE_LISTS:
            result = get_threat_list(args.THREAT, args.LIMIT)
            if result:
                pprint(result)
        else:
            print(f"Error: Threat list '{args.THREAT}' is not recognized. Use -list to see available lists.")
    else:
        parser.print_help()