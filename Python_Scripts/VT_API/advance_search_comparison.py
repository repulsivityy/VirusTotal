##############
# Advance Search to get # offiles with >1 detection in a given time period (country vs global stats)
##############

import json
import os
from pprint import pprint
import urllib
import requests

#countrycode = input("Enter country code")
firstseen = "2024-05-01+"
lastseen = "2024-05-14-"
#firstseen = input("Enter First Seen Start Date (eg 2023-12-01+):")
#lastseen = input("Enter First Seen End Date (eg 2023-12-31-):")

FILE = 'entity:file submitter:au fs:'+ firstseen +' fs:'+ lastseen
FILE_DETECT = 'entity:file submitter:au fs:'+ firstseen +' fs:'+ lastseen +' p:1+'
FILE_DETECT_GLOBAL = 'entity:file fs:'+ firstseen +' fs:'+ lastseen +' p:1+'
"""
URL = 'entity:url submitter:au fs:'+ firstseen + ' fs:'+ lastseen
URL_DETECT = 'entity:url submitter:au fs:'+ firstseen +' fs:'+lastseen +' p:1+'
DOMAIN = 'entity:domain tld:au AND ((last_update_date:'+ lastseen +' AND last_update_date:'+ firstseen +') OR (last_modification_date:'+ lastseen +' AND last_modification_date:'+ firstseen +'))'
DOMAIN_DETECT = 'entity:domain tld:au AND ((last_update_date:'+ lastseen + ' AND last_update_date:'+ firstseen +') OR (last_modification_date:'+ lastseen +' AND last_modification_date:'+ firstseen +')) p:1+'
IP = 'entity:ip country:au last_modification_date:'+ lastseen +' last_modification_date:'+ firstseen
IP_DETECT = 'entity:ip country:au last_modification_date:'+ lastseen +' last_modification_date:'+ firstseen +' p:1+'
"""
LIMIT = '10'  # Max is 300 results
ORDER = 'last_submission_date'  # See below for order. Default is last_submission for files and url, and last_modification for domains and IP
#ORDER_1 = 'last_modification_date'

class color:
    red = '\033[91m'
    darkcyan = '\033[36m'
    end = '\033[0m'

def file(query):
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&order={ORDER}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()

    # Extract and print the total_hits field
    print(f"Query is: " + FILE)
    print(color.darkcyan + f"Total hits: {res.json()['meta']['total_hits']}" + color.end)

def file_detect(query):
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&order={ORDER}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()

    # Extract and print the total_hits field
    print(f"Query is : " + FILE_DETECT)
    print(color.red + f"Total hits with detection: {res.json()['meta']['total_hits']}" + color.end)

def file_detect_global(query):
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&order={ORDER}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()

    # Extract and print the total_hits field
    print(f"Query is : " + FILE_DETECT_GLOBAL)
    print(color.red + f"Total hits with detection: {res.json()['meta']['total_hits']}" + color.end)
"""
def url(query):
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&order={ORDER}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()

    # Extract and print the total_hits field
    print(f"Query is: " + URL)
    print(color.darkcyan + f"Total hits: {res.json()['meta']['total_hits']}" + color.end)

def url_detect(query):
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&order={ORDER}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()

    # Extract and print the total_hits field
    print(f"Query is : " + URL_DETECT)
    print(color.red + f"Total hits with detection: {res.json()['meta']['total_hits']}" + color.end)

def domain(query):
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&order={ORDER_1}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()

    # Extract and print the total_hits field
    print(f"Query is: " + DOMAIN)
    print(color.darkcyan + f"Total hits: {res.json()['meta']['total_hits']}" + color.end)

def domain_detect(query):
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&order={ORDER_1}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()

    # Extract and print the total_hits field
    print(f"Query is: " + DOMAIN_DETECT)
    print(color.red + f"Total hits with detection: {res.json()['meta']['total_hits']}" + color.end)

def ip(query):
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&order={ORDER_1}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()

    # Extract and print the total_hits field
    print(f"Query is: " + IP)
    print(color.darkcyan + f"Total hits: {res.json()['meta']['total_hits']}" + color.end)

def ip_detect(query):
    url = f'https://www.virustotal.com/api/v3/intelligence/search?query={urllib.parse.quote(query)}&order={ORDER_1}&limit={LIMIT}&descriptors_only=false'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(url, headers=headers)
    res.raise_for_status()

    # Extract and print the total_hits field
    print(f"Query is: " + IP_DETECT)
    print(color.red + f"Total hits with detection: {res.json()['meta']['total_hits']}" + color.end)
"""
## output section
#print(DOMAIN, "\n" + DOMAIN_DETECT)

print("\n##### Files #####")
file(FILE)
file_detect(FILE_DETECT)
file_detect_global(FILE_DETECT_GLOBAL)
#print("\n##### URLs #####")
#url(URL)
#url_detect(URL_DETECT)
#print("\n##### Domains #####")
#domain(DOMAIN)
#domain_detect(DOMAIN_DETECT)
#print("\n##### IPs #####\n")
#ip(IP)
#ip_detect(IP_DETECT)

