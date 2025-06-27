#####################################
# Version 2.0
# This script analyzes IP addresses using VirusTotal and Shodan.io.
# It categorizes IPs based on VirusTotal detections and fetches additional
# information for suspicious and malicious IPs.
#
# Requirements:
# - VirusTotal API Key (set as environment variable VT_APIKEY)
# - Shodan.io API Key (set as environment variable SHODAN_APIKEY)
#
# Usage:
# 1. Create a CSV file (e.g., `ips.csv`) with one IP address per line.
# 2. Run the script: `python GetIpAddr_minThreshold.py <path_to_your_ips.csv>`
#    (e.g., `python GetIpAddr_minThreshold.py ips.csv`)
# 3. Enter the minimum detection threshold when prompted.
#
# Author: dominicchua@
#####################################

import requests
import csv
import datetime
import os
import shodan
import sys
import argparse
from typing import List, Dict, Optional

VT_API_BASE_URL = "https://www.virustotal.com/api/v3"

# ANSI escape codes for colored output
class Color:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'

# API Keys
VT_API_KEY = os.environ.get('VT_APIKEY')
SHODAN_API_KEY = os.environ.get('SHODAN_APIKEY')

if not VT_API_KEY:
    print(f"{Color.RED}Error: VT_APIKEY environment variable not set.{Color.RESET}")
    sys.exit(1)
if not SHODAN_API_KEY:
    print(f"{Color.RED}Error: SHODAN_APIKEY environment variable not set.{Color.RESET}")
    sys.exit(1)

shodan_api = shodan.Shodan(SHODAN_API_KEY)

# Function to read IP addresses from a CSV file
def read_ips_from_csv(file_path: str) -> List[str]:
    """Reads IP addresses from a CSV file."""
    ips = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if row and row[0].strip():
                    ips.append(row[0].strip())
        return ips
    except FileNotFoundError:
        print(f"{Color.RED}Error: Input file '{file_path}' not found.{Color.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Color.RED}Error reading CSV file '{file_path}': {e}{Color.RESET}")
        sys.exit(1)

# Function to get the minimum detection threshold from the user
def get_min_detection_threshold() -> int:
    """Prompts the user for the minimum detection threshold."""
    while True:
        user_input = input("Enter minimum detection threshold (q to quit): ").strip()
        if user_input.lower() == "q":
            print("Quitting...")
            sys.exit(0)
        try:
            min_detect = int(user_input)
            if min_detect < 0:
                print(f"{Color.YELLOW}Please enter a non-negative integer.{Color.RESET}")
                continue
            print(f"You entered: {min_detect} as the minimum detection threshold\n")
            return min_detect
        except ValueError:
            print(f"{Color.YELLOW}Invalid input. Please enter an integer.{Color.RESET}")

# Function to fetch VirusTotal IP address report
def get_vt_ip_report(ip_address: str) -> Optional[Dict]:
    """Fetches the VirusTotal IP address report."""
    url = f"{VT_API_BASE_URL}/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"{Color.YELLOW}Warning: IP {ip_address} not found on VirusTotal.{Color.RESET}")
        else:
            print(f"{Color.RED}Error fetching VT report for {ip_address}: HTTP {e.response.status_code} - {e.response.text}{Color.RESET}")
    except requests.exceptions.RequestException as e:
        print(f"{Color.RED}Network error fetching VT report for {ip_address}: {e}{Color.RESET}")
    return None

# Function to check Shodan for information
def get_shodan_info(ip_address: str) -> Optional[Dict]:
    """Fetches Shodan.io information for an IP address."""
    try:
        return shodan_api.host(ip_address)
    except shodan.exception.APIError as e:
        if str(e) == "No information available for that IP.":
            print(f"{Color.YELLOW}No Shodan information available for IP: {ip_address}{Color.RESET}")
        else:
            print(f"{Color.RED}Shodan API error for IP {ip_address}: {e}{Color.RESET}")
    except Exception as e:
        print(f"{Color.RED}Unexpected error fetching Shodan info for {ip_address}: {e}{Color.RESET}")
    return None

# Function to get VirusTotal relationships for an IP address
def get_vt_ip_relationships(ip_address: str) -> Dict:
    """Fetches related URLs and referrer files from VirusTotal for an IP."""
    relationships = {
        "last_final_url": "N/A",
        "url_malicious_detections": 0,
        "referral_files_count": 0,
        "files_malicious_detections": 0
    }
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    # Get associated URLs
    try:
        url_endpoint = f"{VT_API_BASE_URL}/ip_addresses/{ip_address}/urls?limit=1"
        response = requests.get(url_endpoint, headers=headers, timeout=15)
        response.raise_for_status()
        obj_data = response.json()
        if obj_data.get("data"):
            relationships["last_final_url"] = obj_data["data"][0].get("attributes", {}).get("last_final_url", "N/A")
            relationships["url_malicious_detections"] = obj_data["data"][0].get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    except requests.exceptions.RequestException as e:
        print(f"{Color.RED}Error fetching VT URLs for {ip_address}: {e}{Color.RESET}")

    # Get referrer files
    try:
        files_endpoint = f"{VT_API_BASE_URL}/ip_addresses/{ip_address}/referrer_files?limit=1"
        response = requests.get(files_endpoint, headers=headers, timeout=15)
        response.raise_for_status()
        ref_files = response.json()
        relationships["referral_files_count"] = ref_files.get("meta", {}).get("count", 0)
        if ref_files.get("data"):
            relationships["files_malicious_detections"] = ref_files["data"][0].get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    except requests.exceptions.RequestException as e:
        print(f"{Color.RED}Error fetching VT referrer files for {ip_address}: {e}{Color.RESET}")

    return relationships

def main():
    parser = argparse.ArgumentParser(description="Analyze IP addresses using VirusTotal and Shodan.io.")
    parser.add_argument("input_file", help="Path to the CSV file containing IP addresses (one per line).")
    args = parser.parse_args()

    all_ips = read_ips_from_csv(args.input_file)
    if not all_ips:
        print(f"{Color.YELLOW}No IP addresses found in '{args.input_file}'. Exiting.{Color.RESET}")
        return

    print(f"Found {len(all_ips)} IP addresses to check: {all_ips}")
    min_detection_threshold = get_min_detection_threshold()

    # Store results for all IPs
    ip_results = {}

    print(f"\n{Color.BOLD}##################################{Color.RESET}")
    print(f"{Color.BOLD}VirusTotal IP Analysis{Color.RESET}")
    print(f"{Color.BOLD}##################################{Color.RESET}")

    for ip_address in all_ips:
        print(f"Analyzing {ip_address}...")
        vt_report = get_vt_ip_report(ip_address)
        
        malicious_detections = 0
        if vt_report and vt_report.get("data") and vt_report["data"].get("attributes"):
            malicious_detections = vt_report["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", 0)
        
        ip_results[ip_address] = {
            "vt_malicious_detections": malicious_detections,
            "shodan_info": None,
            "vt_relationships": None,
            "category": "good" # Default category
        }

        if malicious_detections >= min_detection_threshold:
            ip_results[ip_address]["category"] = "malicious"
            print(f"{Color.RED}{ip_address} is malicious with {malicious_detections} detections.{Color.RESET}")
        elif malicious_detections > 0:
            ip_results[ip_address]["category"] = "unknown"
            print(f"{Color.YELLOW}{ip_address} is unknown with {malicious_detections} detections.{Color.RESET}")
        else:
            print(f"{Color.GREEN}{ip_address} seems harmless with {malicious_detections} detections.{Color.RESET}")

    # Separate IPs by category for summary and detailed reporting
    malicious_ips = [ip for ip, data in ip_results.items() if data["category"] == "malicious"]
    unknown_ips = [ip for ip, data in ip_results.items() if data["category"] == "unknown"]
    good_ips = [ip for ip, data in ip_results.items() if data["category"] == "good"]

    today = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{Color.BOLD}##################################{Color.RESET}")
    print(f"{Color.BOLD}Summary Report ({today}){Color.RESET}")
    print(f"{Color.BOLD}##################################{Color.RESET}")
    print(f"Total IPs processed: {len(all_ips)}")
    print(f"Malicious IPs (>= {min_detection_threshold} detections): {len(malicious_ips)}")
    print(f"Unknown IPs (1 to {min_detection_threshold-1} detections): {len(unknown_ips)}")
    print(f"Good IPs (0 detections): {len(good_ips)}")

    # Malicious IPs
    if malicious_ips:
        print(f"\n{Color.BOLD}##################################{Color.RESET}")
        print(f"{Color.BOLD}Detailed Report: Malicious IPs{Color.RESET}")
        print(f"{Color.BOLD}##################################{Color.RESET}")
        print(f"Getting additional information from Shodan.io for {len(malicious_ips)} malicious IP(s)...\n")
        for ip_address in malicious_ips:
            shodan_data = get_shodan_info(ip_address)
            if shodan_data:
                print(f"{Color.BOLD}{ip_address}{Color.RESET} - Shodan Info:")
                print(f"  Hostnames: {shodan_data.get('hostnames', 'N/A')}")
                print(f"  Ports: {shodan_data.get('ports', 'N/A')}")
                print(f"  OS: {shodan_data.get('os', 'N/A')}\n")
            else:
                print(f"{Color.BOLD}{ip_address}{Color.RESET} - No Shodan info available.\n")

    # Unknown IPs
    if unknown_ips:
        print(f"\n{Color.BOLD}##################################{Color.RESET}")
        print(f"{Color.BOLD}Detailed Report: Unknown IPs{Color.RESET}")
        print(f"{Color.BOLD}##################################{Color.RESET}")
        print(f"Getting additional information for {len(unknown_ips)} unknown IP(s)...\n")
        for ip_address in unknown_ips:
            relationships = get_vt_ip_relationships(ip_address)
            shodan_data = get_shodan_info(ip_address) # Fetch Shodan info here for unknown IPs

            print(f"{Color.BOLD}{ip_address}{Color.RESET}:")
            print(f"  Last known final URL: {relationships['last_final_url']} ({relationships['url_malicious_detections']} malicious detections)")
            print(f"  Referrer files: {relationships['referral_files_count']} ({relationships['files_malicious_detections']} malicious detections)")
            
            if relationships['referral_files_count'] > 0:
                print(f"  Link to VT graph: {Color.GREEN}https://www.virustotal.com/graph/{ip_address}{Color.RESET}")
            
            if shodan_data:
                print(f"  Shodan Hostnames: {shodan_data.get('hostnames', 'N/A')}")
                print(f"  Shodan Ports: {shodan_data.get('ports', 'N/A')}")
                print(f"  Shodan OS: {shodan_data.get('os', 'N/A')}")
            print("") 

    print(f"\n{Color.BOLD}##################################{Color.RESET}")
    print(f"{Color.BOLD}Analysis Complete{Color.RESET}")
    print(f"{Color.BOLD}##################################{Color.RESET}")

if __name__ == "__main__":
    main()