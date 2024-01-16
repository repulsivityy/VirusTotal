# Version 2 - slightly optimised code
# Original code at GetIpAddr.py
# Code is provided as best effort. Use at your own risk
# VirusTotal // dominicchua@google.com

import requests
import datetime
import os

API_KEY = os.environ['VT_APIKEY']
VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses"
DIRECTORY = "<directory>"

def vt_request(url, headers):
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def main():
    ipaddr = []
    bad_ipaddr = []

    with open(DIRECTORY + 'GetIpAddr.csv', 'r') as ipaddr_input:
        ipaddr = [i.strip() for i in ipaddr_input]

    print("You entered:", ipaddr)

    while True:
        user_input = input("Enter minimum detection threshold (q to quit): ")
        if user_input.lower() == "q":
            print("Quitting...")
            return
        try:
            min_detect = int(user_input)
            print("You entered:", min_detect, "as the minimum detection threshold\n")
            break
        except ValueError:
            print("Invalid input. Please enter an integer")

    for ip in ipaddr:
        url = f"{VT_API_URL}/{ip}"
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }
        try:
            data = vt_request(url, headers)
            malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            if malicious_count > min_detect:
                print(ip, "is malicious with", malicious_count, "detections")
                bad_ipaddr.append(ip)
        except requests.exceptions.RequestException as error:
            print("Error occurred:", error)
            continue
   
    size_bad = len(bad_ipaddr)
    size_total = len(ipaddr)
    today = datetime.datetime.now()

    print("\nAs of", today, "these IPs are determined to be malicious:", bad_ipaddr, "\n")
    print(size_bad, "out of", size_total, "inputs has a min of", min_detect, "detections\n")
    print("Getting last final URLs related to these domains and number of files that contain these IP. Please wait.\n")

    for ip in bad_ipaddr:
        url = f"{VT_API_URL}/{ip}/urls?limit=1"
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }
        try:
            obj_data = vt_request(url, headers)
            last_final_url = obj_data["data"][0]["attributes"]["last_final_url"]
            
            url = f"{VT_API_URL}/{ip}/referrer_files?limit=1"
            ref_files = vt_request(url, headers)
            ref_file_count = ref_files["meta"]["count"]
            
            vt_graph_link = f"https://www.virustotal.com/graph/{ip}" if ref_file_count > 1 else ""
            if ref_file_count > 1: 
                print(f"{ip} has the last known final URL of {last_final_url} and have {ref_file_count} files that contain these IPs. Link to VT graph: \033[32m{vt_graph_link} \033[0m")
            else:
                print(f"{ip} has the last known final URL of {last_final_url} and have {ref_file_count} files that contain these IPs")
        except requests.exceptions.RequestException as error:
            print("Error occurred:", error)
            continue

if __name__ == "__main__":
    main()