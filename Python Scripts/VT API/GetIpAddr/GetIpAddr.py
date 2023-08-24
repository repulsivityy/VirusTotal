# Takes inputs from a CSV file and gets results from VT if they are malicious or not
# Code is provided as best effort. Use at your own risk
# VirusTotal // dominicchua@google.com

## To do / Fix ##
# Issue 1: Clean up / Fix the "\n" for each line break in CSV file
# Issue 2: Additional URL objects having issues

import requests
import csv
import datetime

#Create an empty list to hold indicators
ipaddr = []
bad_ipaddr = []
good_ipaddr = []


working_directory = "<PATH TO DIRECTORY>"
api_key = "API_KEY"

with open(working_directory+'GetIpAddr.csv', 'r') as ipaddr_input:
    for i in ipaddr_input:
        #i = [item.replace('\n', '') for item in i]
        ipaddr.append(i)

#Creates a loop to put objects into the list
#for i in range(1):
#    ipaddr.append(input("Enter IP address: "))

print("You entered: ", ipaddr)

try: 
    for ipadd in ipaddr:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipadd}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        response = requests.get(url, headers=headers)
        #print(response.text)
        data = response.json() #parse response into a dictionary
        if (data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 1): #checks for > 1 detections
            print(ipadd, "is malicious with", data["data"]["attributes"]["last_analysis_stats"]["malicious"], "detections")
            bad_ipaddr.append(ipadd)
        else:
            #print(ipadd, "is not malicious")
            good_ipaddr.append(ipadd)


except Exception as error:
    print("Error occured", error) # print reason for error

size_bad = len(bad_ipaddr)
size_good = len(good_ipaddr)
size_total = len(ipaddr)
today = datetime.datetime.now()

print("\nAs of", today, "these IPs are determined to be malicious: ", bad_ipaddr, "\n")
print(size_bad, "out of", size_total, "inputs are malicious\n")
print("Getting last final URLs related to these domains. Please wait.\n")

for b in bad_ipaddr:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{b}/urls?limit=1"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
#    response = requests.get(url, headers=headers)
    obj_data = response.json()
    #print(response.text)
    print(obj_data["data"])