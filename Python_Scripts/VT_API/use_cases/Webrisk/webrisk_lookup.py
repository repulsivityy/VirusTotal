import requests
import json
import os
import urllib

api_key = os.environ['WEBRISK_APIKEY']
# Change the URL to the URL you are checking
check_url = "http://ratenow.site/"


def check_uri(url):
    url = f'https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&uri={urllib.parse.quote(url)}&key={api_key}'
    response = requests.get(url)
    data = response.json()
    print(data)
    #return data

check_uri(check_url)