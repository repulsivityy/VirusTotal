# Takes inputs from a CSV file and gets results from VT if they are malicious or not
# Issue 1: Clean up / Fix the "\n" for each line break in CSV file

import requests
import csv

#Create an empty list to hold indicators
ipaddr = []
bad_ipaddr = []
good_ipaddr = []

working_directory = "/Users/dominicchua/Google Drive/My Drive/Github/VirusTotal/Python Scripts/"
api_key = "a00dca87920c02ad7e7fcae8785d7fb848e97269b952180d2411ad66ec526316"

with open(working_directory+'GetIpAddr.csv', 'r', newline="\n") as ipaddr_input:
    for i in ipaddr_input:
        #i = [item.replace('\n', '') for item in i]
        ipaddr.append(i)

#Creates a loop to put objects into the list
#for i in range(2):
#    ipaddr.append(input("Enter IP address: "))

print("You entered: ", ipaddr)

try: 
    for ipadd in ipaddr:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipadd}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key #dominic api key
        }
        response = requests.get(url, headers=headers)
        #print(response.text)
        data = response.json() #parse response into a dictionary
        if (data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 1): #checks for > 1 detections
            print(ipadd, "is malicious")
            bad_ipaddr.append(ipadd)
        else:
            #print(ipadd, "is not malicious")
            good_ipaddr.append(ipadd)
           
except Exception as error:
    print("Error occured", error) # print reason for error

size_bad = len(bad_ipaddr)
size_good = len(good_ipaddr)
size_total = len(ipaddr)
print("\nThese IPs are determined to be malicious: ", bad_ipaddr, "\n")
print(size_bad, "out of", size_total, "inputs are malicious\n")
