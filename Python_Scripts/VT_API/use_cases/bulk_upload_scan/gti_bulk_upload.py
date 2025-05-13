#####################################
# Purpose: To automatically upload files to VT, get the report, and return the results in a csv file (see gti_results.csv as example)
# Code is provided as best effort. Use at your own risk
# VirusTotal/GTI // dominicchua@google.com
#
# requirements:
# - VirusTotal / Google Threat Intelligence API Key 
# - VirusTotal Enterprise / GTI Standard / Enterprise / Enterprise + license
#
# Usage: 
# export GTI_APIKEY="<APIKEY>"
# Update INPUT_DIR, OUTPUT_CSV, WAIT_SECONDS, MAX_WORKERS as needed
#
# $ python gti_upload.py  
#####################################

import os
import hashlib
import requests
import time
import csv
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm # Optional: for progress bars (pip install tqdm)


# Modify these paths and settings as needed
INPUT_DIR = "<destination>"  # e.g., "C:/Users/YourUser/Desktop/FilesToScan" or "./files_to_scan"
OUTPUT_CSV = "gti_results.csv"
WAIT_SECONDS = 300  # 5 minutes
MAX_WORKERS = 10    # Number of concurrent uploads/downloads
X_TOOL_HEADER = "bulkupload" # Value for the x-tool header

VT_API_URL = 'https://www.virustotal.com/api/v3'
FILE_SIZE_LIMIT_BYTES = 32 * 1024 * 1024  # 32 MB in bytes, do not change as this affects large file upload to VT/GTI

# Timeouts for requests (in seconds)
TIMEOUT_GET_UPLOAD_URL = 60
TIMEOUT_FILE_UPLOAD = 600 # 10 minutes, adjust if uploading very large files often
TIMEOUT_GET_REPORT = 60

def get_api_key():
    """Fetches the API key from the environment variable."""
    api_key = os.getenv("GTI_APIKEY")
    if not api_key:
        print("Error: Environment variable GTI_APIKEY not set.")
        print("Please set your GTI API key as an environment variable.")
        print("Example (Linux/macOS): export GTI_APIKEY='yourkey'")
        print("Example (Windows CMD): set GTI_APIKEY=yourkey'")
        print("Example (Windows PowerShell): $Env:GTI_APIKEY='yourkey'")
        sys.exit(1)
    return api_key

def calculate_sha256(filepath):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"Warning: File not found during hashing: {filepath}")
        return None
    except Exception as e:
        print(f"Error hashing file {filepath}: {e}")
        return None

def upload_file_to_vt(api_key, filepath, filename):
    """Uploads a single file to GTI, handling large files appropriately."""
    file_hash = calculate_sha256(filepath)
    if not file_hash:
        return {'filename': filename, 'hash': None, 'status': 'hashing_error'}

    try:
        file_size = os.path.getsize(filepath)
    except OSError as e:
        print(f"Error getting file size for {filename}: {e}")
        return {'filename': filename, 'hash': file_hash, 'status': 'filesize_error'}

    upload_target_url = None
    actual_upload_headers = {}

    if file_size > FILE_SIZE_LIMIT_BYTES:
        print(f"File {filename} is > 32MB ({file_size // (1024*1024)}MB). Getting special upload URL...")
        get_url_endpoint = f"{VT_API_URL}/files/upload_url"
        headers_for_get_url = {
            'x-apikey': api_key,
            'accept': 'application/json',
            'x-tool': X_TOOL_HEADER
        }
        try:
            get_url_response = requests.get(get_url_endpoint, headers=headers_for_get_url, timeout=TIMEOUT_GET_UPLOAD_URL)
            get_url_response.raise_for_status()
            
            response_json = get_url_response.json()
            upload_target_url = response_json.get('data')
            
            if not upload_target_url:
                print(f"Error: Could not retrieve special upload URL for {filename}. Response: {response_json}")
                return {'filename': filename, 'hash': file_hash, 'status': 'upload_url_missing'}
            
            actual_upload_headers = {
                'x-apikey': api_key,
                'accept': 'application/json',
                'x-tool': X_TOOL_HEADER
            }
            print(f"Obtained special upload URL for {filename}.")

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                 print(f"Error getting special upload URL for {filename}: Unauthorized (HTTP {e.response.status_code}). Check API key (GTI_APIKEY).")
                 raise SystemExit("API Key invalid - exiting.")
            print(f"HTTP error getting special upload URL for {filename}: {e} - Response: {e.response.text}")
            return {'filename': filename, 'hash': file_hash, 'status': 'upload_url_http_error'}
        except requests.exceptions.RequestException as e:
            print(f"Network error getting special upload URL for {filename}: {e}")
            return {'filename': filename, 'hash': file_hash, 'status': 'upload_url_request_error'}
        except ValueError: 
            print(f"Error decoding upload URL response for {filename}. Response: {get_url_response.text if 'get_url_response' in locals() else 'N/A'}")
            return {'filename': filename, 'hash': file_hash, 'status': 'upload_url_json_error'}
            
    else: # File is 32MB or smaller
        upload_target_url = f"{VT_API_URL}/files"
        actual_upload_headers = {
            'x-apikey': api_key,
            'accept': 'application/json',
            'x-tool': X_TOOL_HEADER
        }

    if not upload_target_url:
        print(f"Internal Error: Upload target URL not set for {filename}.")
        return {'filename': filename, 'hash': file_hash, 'status': 'internal_url_error'}

    try:
        with open(filepath, 'rb') as f:
            files_payload = {'file': (filename, f, 'application/octet-stream')}
            response = requests.post(upload_target_url, headers=actual_upload_headers, files=files_payload, timeout=TIMEOUT_FILE_UPLOAD)

        if response.status_code == 200:
            print(f"Successfully uploaded: {filename} (Hash: {file_hash})")
            return {'filename': filename, 'hash': file_hash, 'status': 'uploaded'}
        elif response.status_code == 409 and upload_target_url == f"{VT_API_URL}/files":
            print(f"File already known to VT: {filename} (Hash: {file_hash})")
            return {'filename': filename, 'hash': file_hash, 'status': 'known'}
        elif response.status_code == 401: 
            print(f"Error uploading {filename}: Unauthorized (HTTP {response.status_code}). Review API key or upload process.")
            if upload_target_url == f"{VT_API_URL}/files": # Only for direct /files, as special URL auth might differ slightly
                raise SystemExit("API Key invalid for direct /files POST - exiting.")
            return {'filename': filename, 'hash': file_hash, 'status': 'upload_auth_error'}
        elif response.status_code == 429:
            print(f"Error uploading {filename}: Rate limit exceeded (HTTP {response.status_code}). Consider reducing MAX_WORKERS or waiting.")
            return {'filename': filename, 'hash': file_hash, 'status': 'rate_limited'}
        else: 
            print(f"Error uploading {filename}: HTTP {response.status_code} - {response.text}")
            return {'filename': filename, 'hash': file_hash, 'status': 'upload_error'}

    except requests.exceptions.RequestException as e:
        print(f"Network or request error uploading {filename}: {e}")
        return {'filename': filename, 'hash': file_hash, 'status': 'network_error'}
    except Exception as e:
        print(f"Unexpected error uploading file {filename}: {e}")
        return {'filename': filename, 'hash': file_hash, 'status': 'unknown_error'}


def get_vt_report(api_key, file_hash):
    """Retrieves the file report from GTI using its hash."""
    default_na = 'N/A'
    base_return = {
        'hash': file_hash,
        'status': 'unknown_error', 
        'ratio': default_na,
        'popular_threat_category': default_na,
        'gti_threat_score': default_na
    }

    if not file_hash:
        base_return['status'] = 'no_hash_for_report'
        return base_return

    url = f"{VT_API_URL}/files/{file_hash}"
    headers = {
        'x-apikey': api_key,
        'accept': 'application/json',
        'x-tool': X_TOOL_HEADER
    }

    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT_GET_REPORT)

        if response.status_code == 200:
            result = response.json()
            attributes = result.get('data', {}).get('attributes', {})
            if attributes:
                stats = attributes.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                undetected = stats.get('undetected', 0)
                harmless = stats.get('harmless', 0)

                total_scans = malicious + suspicious + harmless + undetected
                detection_ratio = default_na
                if total_scans > 0:
                    detection_ratio = f"{malicious}/{total_scans}"
                else:
                    if 'last_analysis_date' not in attributes:
                         detection_ratio = "Pending Analysis"
                
                base_return['ratio'] = detection_ratio
                base_return['status'] = 'completed'

                popular_threat_info = attributes.get('popular_threat_classification')
                if popular_threat_info:
                    categories = popular_threat_info.get('popular_threat_category')
                    if categories and isinstance(categories, list) and len(categories) > 0:
                        base_return['popular_threat_category'] = categories[0].get('value', default_na)
                
                gti_assessment_info = attributes.get('gti_assessment')
                if gti_assessment_info:
                    threat_score_info = gti_assessment_info.get('threat_score')
                    if threat_score_info:
                        score_value = threat_score_info.get('value')
                        base_return['gti_threat_score'] = str(score_value) if score_value is not None else default_na
                
                return base_return
            else:
                print(f"Report format unexpected for hash: {file_hash}. Response: {result}")
                base_return['status'] = 'report_format_error'
                return base_return
        elif response.status_code == 404:
            print(f"Report not found for hash: {file_hash}. May still be queued or unknown.")
            base_return['status'] = 'not_found'
            base_return['ratio'] = 'Not Found/Pending'
            return base_return
        elif response.status_code == 401:
            print(f"Error fetching report for {file_hash}: Unauthorized (HTTP {response.status_code}). Check API key (GTI_APIKEY).")
            raise SystemExit("API Key invalid - exiting.")
        elif response.status_code == 429:
            print(f"Error fetching report for {file_hash}: Rate limit exceeded (HTTP {response.status_code}).")
            base_return['status'] = 'rate_limited'
            base_return['ratio'] = 'Rate Limited'
            return base_return
        else:
            print(f"Error fetching report for {file_hash}: HTTP {response.status_code} - {response.text}")
            base_return['status'] = 'fetch_error'
            return base_return

    except requests.exceptions.RequestException as e:
        print(f"Network or request error fetching report for {file_hash}: {e}")
        base_return['status'] = 'network_error'
        return base_return
    except ValueError: 
        print(f"Error decoding report response for {file_hash}. Response: {response.text if 'response' in locals() else 'N/A'}")
        base_return['status'] = 'report_json_error'
        return base_return
    except Exception as e:
        print(f"Unexpected error fetching report for hash {file_hash}: {e}")
        return base_return

# --- Main Execution ---
if __name__ == "__main__":
    api_key = get_api_key()

    input_dir = INPUT_DIR
    output_csv = OUTPUT_CSV
    wait_seconds = WAIT_SECONDS
    max_workers = MAX_WORKERS

    if not os.path.isdir(input_dir):
        print(f"Error: Input directory '{input_dir}' not found or is not a directory.")
        print("Please set the INPUT_DIR global variable at the top of the script.")
        sys.exit(1)

    files_to_process = []
    print(f"Scanning directory: {input_dir}")
    for filename in os.listdir(input_dir):
        filepath = os.path.join(input_dir, filename)
        if os.path.isfile(filepath):
            try:
                if os.path.getsize(filepath) > 650 * 1024 * 1024: 
                    print(f"Skipping file {filename}: size exceeds 650MB limit.")
                    continue
                files_to_process.append({'filepath': filepath, 'filename': filename})
            except OSError as e:
                print(f"Could not get size for file {filename}, skipping: {e}")


    if not files_to_process:
        print("No suitable files found in the input directory.")
        sys.exit(0)

    print(f"Found {len(files_to_process)} files to process.")

    submitted_files = [] 
    upload_errors_info = [] 
    print(f"\n--- Starting File Uploads (Max Workers: {max_workers}) ---")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(upload_file_to_vt, api_key, f['filepath'], f['filename']) for f in files_to_process]
        for future in tqdm(as_completed(futures), total=len(futures), desc="Uploading Files"):
            try:
                result = future.result() 
                if result:
                    if result.get('hash') and (result['status'] == 'uploaded' or result['status'] == 'known'):
                        submitted_files.append({'filename': result['filename'], 'hash': result['hash']})
                    else:
                        upload_errors_info.append(result) 
            except SystemExit as e: 
                print(f"Exiting due to critical error: {e}")
                executor.shutdown(wait=False, cancel_futures=True)
                sys.exit(1)
            except Exception as e:
                print(f"Critical error processing an upload task result: {e}")


    print(f"\n--- Upload Phase Complete ---")
    print(f"Successfully submitted/found {len(submitted_files)} files for analysis.")
    if upload_errors_info:
        print(f"Encountered issues with {len(upload_errors_info)} files during upload/preprocessing:")


    if not submitted_files:
        print("No files were successfully submitted or found on GTI for analysis. Exiting.")
        if not upload_errors_info : print ("Also no errors recorded during upload phase.")
        sys.exit(0)

    print(f"\nWaiting {wait_seconds} seconds for GTI analysis...")
    for i in range(wait_seconds, 0, -1):
        print(f"  Time remaining: {i} seconds...    \r", end="")
        time.sleep(1)
    print("\nWait complete.                                ")

    report_results = {} 
    report_fetch_errors_info = []
    print(f"\n--- Fetching Analysis Reports (Max Workers: {max_workers}) ---")
    
    unique_hashes_to_fetch = {f['hash'] for f in submitted_files if f['hash']}
    print(f"Fetching reports for {len(unique_hashes_to_fetch)} unique hashes...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(get_vt_report, api_key, file_hash) for file_hash in unique_hashes_to_fetch]
        for future in tqdm(as_completed(futures), total=len(unique_hashes_to_fetch), desc="Fetching Reports"):
            try:
                result = future.result() 
                if result and result.get('hash'):
                    report_results[result['hash']] = {
                        'ratio': result.get('ratio', 'N/A'), 
                        'status': result.get('status', 'Error'),
                        'popular_threat_category': result.get('popular_threat_category', 'N/A'),
                        'gti_threat_score': result.get('gti_threat_score', 'N/A')
                    }
                    if result.get('status') not in ['completed', 'not_found', 'pending_analysis', 'no_hash_for_report']:
                        report_fetch_errors_info.append(result)
            except SystemExit as e:
                print(f"Exiting due to critical error: {e}")
                executor.shutdown(wait=False, cancel_futures=True)
                sys.exit(1)
            except Exception as e:
                print(f"Critical error processing a report task result: {e}")


    print(f"\n--- Report Fetching Complete ---")
    completed_reports_count = sum(1 for res in report_results.values() if res.get('status') == 'completed')
    print(f"Processed reports for {len(report_results)} unique hashes. {completed_reports_count} completed successfully.")
    if report_fetch_errors_info:
         print(f"Encountered issues fetching reports for {len(report_fetch_errors_info)} hashes.")


    print(f"\nWriting results to {output_csv}...")
    final_data_for_csv = []
    default_na = 'N/A'

    fieldnames = [
        'filename', 'sha256_hash', 'detection_ratio', 'report_status', 
        'popular_threat_category', 'gti_threat_score'
    ]

    for file_info in submitted_files:
        file_hash = file_info['hash']
        report_data = report_results.get(file_hash)

        if report_data:
            final_data_for_csv.append({
                'filename': file_info['filename'],
                'sha256_hash': file_hash if file_hash else default_na,
                'detection_ratio': report_data.get('ratio', default_na),
                'report_status': report_data.get('status', 'Report Missing'),
                'popular_threat_category': report_data.get('popular_threat_category', default_na),
                'gti_threat_score': report_data.get('gti_threat_score', default_na)
            })
        else: 
            final_data_for_csv.append({
                'filename': file_info['filename'],
                'sha256_hash': file_hash if file_hash else default_na,
                'detection_ratio': default_na,
                'report_status': 'Report Data Missing Internally',
                'popular_threat_category': default_na,
                'gti_threat_score': default_na
            })

    for error_info in upload_errors_info:
        final_data_for_csv.append({
            'filename': error_info.get('filename', default_na),
            'sha256_hash': error_info.get('hash', default_na),
            'detection_ratio': default_na,
            'report_status': f"Preprocessing/Upload Failed ({error_info.get('status', 'Unknown Error')})",
            'popular_threat_category': default_na,
            'gti_threat_score': default_na
        })
    

    if not final_data_for_csv:
        print("No data to write to CSV.")
    else:
        try:
            with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(final_data_for_csv)
            print(f"Successfully wrote {len(final_data_for_csv)} rows to {output_csv}")
        except Exception as e:
            print(f"Error writing to CSV file {output_csv}: {e}")

    print("\n--- Script Finished ---")