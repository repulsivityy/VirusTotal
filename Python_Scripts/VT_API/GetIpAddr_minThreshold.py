#####################################
# Version 1.3
# Takes inputs from a CSV file and gets results from VT if they are malicious or not
# For IPs deemed malicious (>min_detect) to check with Shodan on open ports, OS, and hostname
# If not determined (between 1 to min_detect), to get last_final_url from these IPs and checks if there are any files that contain/refers to this IP
# Code is provided as best effort. Use at your own risk
# VirusTotal // dominicchua@google.com

# requirements:
# - VirusTotal API Key
# - Shodan.io API Key

# Usage
# 1. put all IPs into a csv file, and update working_directory var

## To do / Fix ##
# optimise the code, can define certain functions
# fix the break points
#####################################

import requests
import csv
import datetime
import os
import shodan  # new for shodan

#Create an empty list to hold indicators
ipaddr = [] # for all IP addresses in CSV
bad_ipaddr = [] # for all indicators that meet min_detection threshold input by user
good_ipaddr = [] # zero detections 
unknown_ipaddr = [] # all indicators >1 detection but <min_detection

working_directory = "<Working Directory>"
api_key = os.environ['VT_APIKEY']
shodan_key = os.environ['SHODAN_APIKEY']  # new for shodan
shodan_api = shodan.Shodan(shodan_key) # for shodan

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
        print("You entered:", min_detect, "as the minimum detection threshold")
        break
    except ValueError:
        print("Invalid input. Please enter an integer")

try: 
    print("\n##################################")
    print("Is Malicious")
    print("##################################")

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

        if (mal_ip >= min_detect): #checks for > min_detect
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
#print("\n##################################")
#print("Is Malicious")
print("\n##################################")
print("As of", today, "these IPs are determined to be malicious:", bad_ipaddr, "\n")
print(size_bad, "out of", size_total, "inputs have with a minimum of", min_detect, "detections.\n")

# Prints output from Shodan for IPs >min_detect
print("Getting additional information from Shodan.io:\n")
try: #uses shodan to get more info on the bad IPs
    for b in bad_ipaddr:
        shodan_info = shodan_api.host(b)
        print(b, "has the following hostnames", shodan_info["hostnames"], ", with the following ports", shodan_info["ports"], ", running on OS", shodan_info["os"])
except Exception as error:
    print("Error occured:", error)


if (size_unknown > 0):

    # Comments for the remaining unknonws
    print("\n##################################")
    print("Is Unknown")
    print("##################################")
    print(size_unknown, "out of", size_total, "are between 1 and", min_detect, "detections. These are the IP addresses:\n", unknown_ipaddr)
    
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

            #last_final_url = obj_data["data"][0]["attributes"]["last_final_url"] # var for last final url
            #url_last_analysis_stats_malicious = obj_data["data"][0]["attributes"]["last_analysis_stats"]["malicious"] # var for # of malicious verdicts for last_final_URL
            # Robustly handle empty "data" list
            if obj_data.get("data"):
                last_final_url = obj_data["data"][0].get("attributes", {}).get("last_final_url", "N/A") 
                url_last_analysis_stats_malicious = obj_data["data"][0].get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            else:
                last_final_url = "N/A"  
                url_last_analysis_stats_malicious = 0

            # Check for referrer files
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{u}/referrer_files?limit=1"
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }
            response = requests.get(url, headers=headers)
            ref_files = response.json()
            # print(response.text)  # Uncomment for debugging
            referral_files = ref_files["meta"]["count"] # var for # of referral_files seen
            # Handle missing attributes for referrer files (ref_files)
            if ref_files.get("data"):
                files_last_analysis_stats_malicious = ref_files["data"][0].get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            else:
                files_last_analysis_stats_malicious = 0

            shodan_info = {}  # Initialize shodan_info as an empty dictionary
            try:
                shodan_info = shodan_api.host(u)
            except shodan.APIError as e:
                if str(e) == "No information available for that IP.":
                    print(f"\nNo Shodan information available for IP: {u}")
                else:
                    print(f"Shodan API error for IP {u}: {e}")

            # Print Shodan info only if it's available
            if shodan_info:
                print("\n", u, "has the following hostnames", shodan_info["hostnames"], ", with the following ports", shodan_info["ports"], ", running on OS", shodan_info["os"])


            if (referral_files > 1): #IF/ELSE to print VT graph link for reference - yes i got lazy here ;(
                print("\033[1m", u, "\033[0;0mhas the last known final URL of", last_final_url, "with", url_last_analysis_stats_malicious, "malicious detections, and", referral_files, "files that contain these IPs, with", files_last_analysis_stats_malicious, "malicious detections. \nLink to VT graph: " + f"\033[92mhttps://www.virustotal.com/graph/{u}\033[0;0m")
            else:
                print(u, "has the last known final URL of", last_final_url, "with", url_last_analysis_stats_malicious, "malicious detections and have", referral_files, "files that contain these IPs")
                
    except shodan.exception.APIError as e:
        print("Shodan API error:", e)
    except Exception as error:
        print("Error occured:", error) # print reason for error

else: 
    print("\nThere are ", size_unknown, "IPs that are between 1 and ", min_detect, "detections.")

print("\n##################################")
print("END")
print("##################################")