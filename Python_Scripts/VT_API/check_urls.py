#####################################
# Version 1
# Takes inputs from a CSV file and gets results from GTI if they are malicious or not

# requirements:
# - Google Threat Intelligence (or VT) API Key

# Usage
# 1. put all URLs into a csv file
# 2. run the script - choose a min_threshold
# 3. if >min_threshold, output to terminal
#####################################


import requests
import csv
import time
import os

VT_URL_REPORT = 'https://www.virustotal.com/api/v3/urls'
VT_ANALYSIS = 'https://www.virustotal.com/api/v3/analyses/'

headers = {
    'x-apikey': os.environ['GTI_APIKEY'],
    "Accept": "application/json",
}

def check_url(url):
    try:
        response = requests.post(VT_URL_REPORT, headers=headers, data={'url': url})

        # Handle specific HTTP error codes
        if response.status_code == 400:
            raise ValueError("Bad request - Invalid URL format")
        elif response.status_code == 403:
            raise PermissionError("Forbidden - Check your API key")
        elif response.status_code in (204, 429):  # Rate limiting
            time.sleep(60)
            return check_url(url)

        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            analysis_url = f"{VT_ANALYSIS}{analysis_id}"

            while True:
                analysis_response = requests.get(analysis_url, headers=headers)
                if analysis_response.status_code == 200:
                    data = analysis_response.json()['data']['attributes']
                    if data['status'] == 'completed':
                        return data.get('stats', {}).get('malicious', 0)
                #time.sleep(10)
        else:
            raise Exception(f"Unexpected error: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Network error for {url}: {e}")
    except (ValueError, PermissionError, Exception) as e:
        print(f"Error checking {url}: {e}")
    return 0  # Return 0 for errors 

while True:
    csv_file = input("Enter the path to your CSV file: ")
    if os.path.exists(csv_file):
        break
    else:
        print("File not found. Please try again.")

while True:
    try:
        min_detections = int(input("Enter the minimum number of detections: "))
        if min_detections >= 0:
            break
        else:
            print("Please enter a non-negative integer.")
    except ValueError:
        print("Invalid input. Please enter an integer.")

with open(csv_file, 'r') as file:
    reader = csv.reader(file)
    for row in reader:
        url = row[0]  # Assuming the first column contains URLs
        detections = check_url(url)

        if detections >= min_detections:
            print(f"{url} has {detections} detections as malicious")