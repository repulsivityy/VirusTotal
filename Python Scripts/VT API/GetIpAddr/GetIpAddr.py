# Version 1.1
# Takes inputs from a CSV file and gets results from VT if they are malicious or not
# If not determined (between 1 to min_detect), to get last_final_url from these IPs and checks if there are any files that contain/refers to this IP
# Code is provided as best effort. Use at your own risk
# VirusTotal // dominicchua@google.com

## To do / Fix ##
# optimise the code, can define certain functions
# fix the break points

import requests
import csv
import datetime

#Create an empty list to hold indicators
ipaddr = [] # for all IP addresses in CSV
bad_ipaddr = [] # for all indicators that meet min_detection threshold input by user
good_ipaddr = [] # zero detections 
unknown_ipaddr = [] # all indicators >1 detection but <min_detection

working_directory = "/Users/dominicchua/Google Drive/My Drive/Github/VirusTotal/Python Scripts/VT API/GetIpAddr/"
api_key = "a00dca87920c02ad7e7fcae8785d7fb848e97269b952180d2411ad66ec526316"

with open(working_directory+'GetIpAddr.csv', 'r') as ipaddr_input:
    for i in ipaddr_input:
        ipaddr.append(i.strip()) # strips leading & trailing whitespace 

print("You entered: ", ipaddr)

while True: 
    user_input = (input("Enter minimum detection threshold (q to quit): ")) # user input of min detection threshold

    if user_input.lower() == "q":
        print("Quitting...")
        break

    try:     
        min_detect = int(user_input)
        print("You entered :", min_detect, "as the minimum detection threshold")
        break
    except ValueError:
        print("Invalid input. Please enter an integer")

try: 
    for ipadd in ipaddr: # API call to check on IP address verdict
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipadd}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        response = requests.get(url, headers=headers)
        #print(response.text)
        data = response.json() #parse response into a dictionary
        mal_ip = data["data"]["attributes"]["last_analysis_stats"]["malicious"] #puts into variable for easy usage

        if (mal_ip > min_detect): #checks for > min_detect 
            print(ipadd, "is malicious with", mal_ip, "detections")
            bad_ipaddr.append(ipadd)
        elif (mal_ip > 1) :
            unknown_ipaddr.append(ipadd)
        else:
            #print(ipadd, "is not malicious")
            good_ipaddr.append(ipadd)

except Exception as error:
    print("Error occured:", error) # print reason for error

# Just counts the length of list
size_bad = len(bad_ipaddr) 
size_good = len(good_ipaddr)
size_unknown= len(unknown_ipaddr)
size_total = len(ipaddr)
today = datetime.datetime.now()

# Some comments 
print("\nAs of", today, "these IPs are determined to be malicious:", bad_ipaddr, "\n")
print(size_bad, "out of", size_total, "inputs have with a minimum of", min_detect, "detections.\n")
print(size_unknown, "out of", size_total, "are between 1 and", min_detect, "detections. These are the IP addresses:\n", unknown_ipaddr)
print("\nGetting last_final_URLs related to these domains and number of files that contain these IP. Please wait.\n")

try: 
    for u in unknown_ipaddr:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{u}/urls?limit=1" # Check for additional URLs
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        response = requests.get(url, headers=headers)
        obj_data = response.json()
        #print(response.text)
        #for d in bad_ipaddr:
        last_final_url = obj_data["data"][0]["attributes"]["last_final_url"] # var for last final url
        url_last_analysis_stats_malicious = obj_data["data"][0]["attributes"]["last_analysis_stats"]["malicious"] # var for # of malicious verdicts for last_final_URL

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{u}/referrer_files?limit=1" # Check for any files that refers to this IP - indication of possible malware
        headers = {
            "accept": "application/json",
            "x-apikey": "a00dca87920c02ad7e7fcae8785d7fb848e97269b952180d2411ad66ec526316"
        }
        response = requests.get(url, headers=headers)
        ref_files = response.json() # parse output into dictionary
        referral_files = ref_files["meta"]["count"] # var for # of referral_files seen
        files_last_analysis_stats_malicious = ref_files["data"][0]["attributes"]["last_analysis_stats"]["malicious"] # var for # of malicious verdicts for referral_files

        if (referral_files > 1): #IF/ELSE to print VT graph link for reference - yes i got lazy here ;(
            print("\033[1m", u, "\033[0;0mhas the last known final URL of", last_final_url, "with", url_last_analysis_stats_malicious, "malicious detections, and", referral_files, "files that contain these IPs, with", files_last_analysis_stats_malicious, "malicious detections. Link to VT graph: " + f"\033[92mhttps://www.virustotal.com/graph/{u}\033[0;0m")
        else:
            print(u, "has the last known final URL of", last_final_url, "with", url_last_analysis_stats_malicious, "malicious detections and have", referral_files, "files that contain these IPs")
except Exception as error:
    print("Error occured:", error) # print reason for error