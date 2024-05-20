import requests
import json
import os
import urllib
import requests
import pprint

api_key = os.environ['WEBRISK_APIKEY']
# Change the URL to the URL you are checking
VT_URL = "http://cashforcars-brisbane.com/cxbshell.php"


def check_uri(url):
    url = f'https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&uri={urllib.parse.quote(url)}&key={api_key}'
    response = requests.get(url)
    data = response.json()
    #print(data)
    #return data

check_uri(VT_URL)