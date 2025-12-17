import requests
import csv
import time
import os
import json
import re  # Import regex library
import concurrent.futures  # <-- FIX 1: Added the missing import

# --- Configuration ---
# Set your API key as an environment variable named 'GTI_APIKEY' for security
GTI_APIKEY = os.getenv('GTI_APIKEY')

if not GTI_APIKEY:
    GTI_APIKEY = 'YOUR_API_KEY_HERE'  # Fallback if env var isn't set
    print("Warning: Using hardcoded API key. Set the GTI_APIKEY environment variable for better security.")

if GTI_APIKEY == 'YOUR_API_KEY_HERE':
    print("ERROR: Please set your GTI_APIKEY in the script or as an environment variable.")
    exit()

while True:
    INPUT_CSV = input("Enter the path to your CSV file: ")
    if os.path.exists(INPUT_CSV):
        break
    else:
        print("File not found. Please try again.")

OUTPUT_CSV = 'output.csv'
MAX_WORKERS = 15  # Number of concurrent analyses

# API Endpoints
REANALYSE_URL = 'https://www.virustotal.com/api/v3/ip_addresses/{}/analyse'
REPORT_URL = 'https://www.virustotal.com/api/v3/ip_addresses/{}'
ANALYSIS_URL = 'https://www.virustotal.com/api/v3/analyses/{}'  # For polling

# Headers including the required 'x-tool' to get gti_assessment
HEADERS = {
    'x-apikey': GTI_APIKEY,
    'Accept': 'application/json',
    'x-tool': 'gti-ip-enrichment-script'  # Name of your tool
}

# --- Helper Functions ---

def read_ips_from_csv(filename):
    """Reads a list of IP addresses from a one-column CSV file."""
    ips = []
    try:
        with open(filename, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header row
            for row in reader:
                if row:  # Ensure row is not empty
                    ips.append(row[0].strip())
        print(f"Read {len(ips)} IPs from {filename}")
        return ips
    except FileNotFoundError:
        print(f"ERROR: Input file '{filename}' not found.")
        return []
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return []

def parse_whois_netname(whois_text):
    """
    Parses the 'NetName:' field from a raw whois text block.
    This is a fallback for when rdap.name is not available.
    """
    if not whois_text:
        return None
    match = re.search(r'^NetName:\s*(.*)', whois_text, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return None

def poll_analysis_completion(analysis_id, ip):
    """Polls the analysis endpoint until it's 'completed'."""
    poll_url = ANALYSIS_URL.format(analysis_id)
    poll_start_time = time.time()
    poll_interval = 15  # Wait 15 seconds between checks
    poll_timeout = 300  # Give up after 5 minutes

    print(f"  Polling analysis for {ip} (ID: {analysis_id})...", end='', flush=True)
    
    while True:
        if time.time() - poll_start_time > poll_timeout:
            print(f"\n  ERROR: Timeout for {ip}")
            return False
        try:
            response = requests.get(poll_url, headers=HEADERS)
            if response.status_code == 200:
                status = response.json().get('data', {}).get('attributes', {}).get('status')
                if status == 'completed':
                    print(f"\n  Analysis complete for {ip}.")
                    return True
                elif status == 'failed':
                    print(f"\n  ERROR: Analysis failed for {ip}.")
                    return False
                else:
                    print(".", end='', flush=True)
            else:
                print(f"\n  ERROR: Polling for {ip} failed with status {response.status_code}.")
                return False
        except requests.RequestException as e:
            print(f"\n  ERROR: Polling request for {ip} failed: {e}")
            return False
        
        time.sleep(poll_interval)

# --- Unit of Work Function (for concurrency) ---

def process_single_ip(ip):
    """
    Processes a single IP: triggers analysis, polls, fetches report, 
    and returns a dictionary for the CSV row.
    """
    print(f"Processing {ip}...")
    analysis_id = None
    
    # 1. Trigger Re-analysis
    try:
        post_response = requests.post(REANALYSE_URL.format(ip), headers=HEADERS)
        if post_response.status_code == 200:
            analysis_id = post_response.json().get('data', {}).get('id')
            print(f"  Successfully requested re-analysis for {ip}.")
        else:
            print(f"  Failed to request re-analysis for {ip}: {post_response.status_code} {post_response.text}")
            # IMPROVEMENT: Use 'status' column for errors
            return {'id': ip, 'status': 'Re-analysis trigger failed'}
    except requests.RequestException as e:
        print(f"  Re-analysis request failed for {ip}: {e}")
        # IMPROVEMENT: Use 'status' column for errors
        return {'id': ip, 'status': f'Request failed: {e}'}

    # 2. Poll for completion
    if not analysis_id or not poll_analysis_completion(analysis_id, ip):
        print(f"  Skipping report fetch for {ip} due to analysis issue.")
        # IMPROVEMENT: Use 'status' column for errors
        return {'id': ip, 'status': 'Analysis did not complete or timed out'}

    # 3. Fetch the full, updated report
    try:
        # Short pause to respect rate limits and allow data to sync post-analysis
        time.sleep(1) 
        
        response = requests.get(REPORT_URL.format(ip), headers=HEADERS)
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            last_analysis = attributes.get('last_analysis_results', {})
            
            # Extract target fields
            gcp_abuse = last_analysis.get('GCP Abuse Intelligence')
            google_sb = last_analysis.get('Google Safebrowsing')
            
            # Robust Netname Extraction
            whois_raw = attributes.get('whois')
            rdap_name = attributes.get('rdap', {}).get('name')
            netname = rdap_name or parse_whois_netname(whois_raw)
            
            # Prepare row for CSV
            output_row = {
                'id': data.get('id', ip),
                'status': 'Success',  # IMPROVEMENT: Add success status
                'gti_assessment': json.dumps(attributes.get('gti_assessment')),
                'GCP_Abuse_Intelligence': json.dumps(gcp_abuse),
                'Google_Safebrowsing': json.dumps(google_sb),
                'last_analysis_stats': json.dumps(attributes.get('last_analysis_stats')),
                'whois_netname': netname
            }
            
            print(f"  Successfully processed report for {ip}.")
            return output_row

        elif response.status_code == 404:
            print(f"  No report found for {ip}. Writing empty row.")
            # IMPROVEMENT: Use 'status' column
            return {'id': ip, 'status': 'Report not found (404)'}
        else:
            print(f"  Failed to get report for {ip}: {response.status_code} {response.text}")
            # IMPROVEMENT: Use 'status' column
            return {'id': ip, 'status': f'Report fetch failed: {response.status_code}'}

    except requests.RequestException as e:
        print(f"  Report request failed for {ip}: {e}")
        # IMPROVEMENT: Use 'status' column
        return {'id': ip, 'status': f'Report request failed: {e}'}
    except json.JSONDecodeError:
        print(f"  Failed to decode JSON response for {ip}")
        # IMPROVEMENT: Use 'status' column
        return {'id': ip, 'status': 'Failed to decode JSON response'}

# --- Main Workflow ---

def main_workflow():
    """
    Main workflow: 
    1. Read IPs from CSV.
    2. Create a ThreadPoolExecutor to process IPs concurrently.
    3. Write all results to the output CSV.
    """
    ip_list = read_ips_from_csv(INPUT_CSV)
    if not ip_list:
        return

    print(f"\n--- Starting Concurrent IP Processing ({MAX_WORKERS} workers) ---")
    
    # IMPROVEMENT: Added 'status' column
    fieldnames = [
        'id',
        'status',
        'gti_assessment',
        'GCP_Abuse_Intelligence',
        'Google_Safebrowsing',
        'last_analysis_stats',
        'whois_netname'
    ]

    with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # 'map' runs 'process_single_ip' for each item in 'ip_list'
            # It collects all results in order before proceeding.
            results = list(executor.map(process_single_ip, ip_list))
            
        # Now, safely write all collected results to the CSV
        for row in results:
            if row:
                writer.writerow(row)

    print(f"\n--- Process Complete ---")
    # FIX 2: Corrected the variable name typo
    print(f"Results written to {OUTPUT_CSV}")

# --- Run the script ---
if __name__ == "__main__":
    main_workflow()  # Call the correct main function