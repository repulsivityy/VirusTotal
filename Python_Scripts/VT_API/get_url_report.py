#####################################
# Usage
# Takes a list of URLs from a CSV file, fetches their VirusTotal reports,
# and outputs the results to the terminal or a CSV file.

# requirements:
# - VirusTotal API Key (set as environment variable VT_APIKEY)

# author: dominicchua@ (adapted by Gemini Code Assist)
# version: 1.0
# USE AT YOUR OWN RISK
#####################################

import requests
import csv
import json
import os
import argparse
import pathlib
import base64
import datetime
import hashlib # For generating VT GUI link

VT_API_URL_URL_INFO = "https://www.virustotal.com/api/v3/urls/{}"

# Define fields to extract from the URL report attributes and their display names
URL_REPORT_FIELDS = {
    "last_analysis_stats.malicious": "malicious_detections",
    "last_analysis_stats.harmless": "harmless_detections",
    "last_analysis_stats.suspicious": "suspicious_detections",
    "last_analysis_stats.undetected": "undetected_detections",
    "gti_assessment.threat_score.value": "gti_threat_score",
    "gti_assessment.severity.value": "gti_severity",
    "gti_assessment.verdict.value": "gti_verdict",
}

def get_url_report(api_key, url_to_check):
    """Fetches the VirusTotal report for a given URL."""
    headers = {
        "x-apikey": api_key,
        "x-tool": "get_url_report_script"
    }
    # Base64 encode the URL (URL-safe, no padding)
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    
    url = VT_API_URL_URL_INFO.format(url_id)
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        return response.json(), "Success"
    except requests.exceptions.HTTPError as http_err:
        status_message = f"HTTP Error: {http_err}"
        if response is not None:
            if response.status_code == 401:
                status_message = "Unauthorized API Key"
                print("Error: Unauthorized. Please check your API key.")
            elif response.status_code == 404:
                status_message = "URL Not Found on VirusTotal"
                print(f"Error: URL '{url_to_check}' not found on VirusTotal. It might not have been scanned yet.")
            else:
                try:
                    error_details = response.json()
                    status_message = f"API Error: {error_details.get('error', {}).get('message', 'Unknown API error')}"
                    print(f"API Error details: {json.dumps(error_details, indent=2)}")
                except json.JSONDecodeError:
                    status_message = f"Could not parse API error response. Status: {response.status_code}, Body: {response.text[:100]}..."
                    print(status_message)
        return None, status_message
    except requests.exceptions.Timeout:
        status_message = "Request Timed Out"
        print(f"Request timed out while fetching report for URL: {url_to_check}")
        return None, status_message
    except requests.exceptions.RequestException as req_err:
        status_message = f"Network/Request Error: {req_err}"
        print(f"Request error occurred: {req_err}")
        return None, status_message

def extract_url_report_data(url_input, report_json):
    """Extracts relevant data from the VirusTotal URL report JSON."""
    # Initialize extracted_data with default "N/A" values and a status
    extracted_data = {
        "input_url": url_input,
        "status": "Failed to retrieve report", # Default status, will be updated
        "malicious_detections": "N/A",
        "harmless_detections": "N/A",
        "suspicious_detections": "N/A",
        "undetected_detections": "N/A",
        "gti_threat_score": "N/A",
        "gti_severity": "N/A",
        "gti_verdict": "N/A",
        "vt_gui_link": f"https://www.virustotal.com/gui/url/{hashlib.sha256(url_input.encode()).hexdigest()}",
    }

    if not report_json:
        # If report_json is None, it means the API call failed (e.g., 404, timeout, etc.)
        # The status will be set by the calling function (main)
        return extracted_data

    if "data" not in report_json:
        extracted_data["status"] = "Invalid report format from VT"
        return extracted_data

    data = report_json["data"]
    attributes = data.get("attributes", {})
    
    extracted_data["status"] = "Success" # Set status to success if data is found

    for field_path, display_name in URL_REPORT_FIELDS.items():
        # Handle nested fields like 'last_analysis_stats.malicious'
        parts = field_path.split('.')
        current_value = attributes
        found = True
        for part in parts:
            if isinstance(current_value, dict) and part in current_value:
                current_value = current_value[part]
            else:
                found = False
                break
        
        if found and current_value is not None:
            extracted_data[display_name] = current_value
        else:
            extracted_data[display_name] = "N/A" # Indicate missing data

    return extracted_data

def print_report_to_terminal(report_data):
    """Prints a single URL report to the terminal."""
    if not report_data:
        print("No data to display.")
        return

    print(f"\n--- URL Report for: {report_data.get('input_url', 'N/A')} (Status: {report_data.get('status', 'N/A')}) ---")
    for key, value in report_data.items():
        if key in ["input_url", "status"]: # Already printed in header or status line
            continue
        # Skip printing N/A values for cleaner terminal output, but keep them in CSV
        if value == "N/A": continue 
        print(f"  {key.replace('_', ' ').title()}: {value}")

def write_reports_to_csv(reports_list, output_file_path):
    """Writes a list of URL reports to a CSV file."""
    if not reports_list:
        print("No reports to write to CSV.")
        return

    # Collect all possible keys from all reports to ensure all columns are present
    all_keys = set()
    for report in reports_list:
        all_keys.update(report.keys())
    
    # Define the preferred order of columns for better readability
    ordered_fieldnames = ["input_url", "status",
                          "malicious_detections", "harmless_detections", "suspicious_detections", "undetected_detections",
                          "gti_threat_score", "gti_severity", "gti_verdict",
                          "vt_gui_link"]
    
    # Add any other keys found that are not in the predefined order
    for key in sorted(list(all_keys)):
        if key not in ordered_fieldnames:
            ordered_fieldnames.append(key)

    try:
        with open(output_file_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=ordered_fieldnames, extrasaction='ignore')
            writer.writeheader()
            for report in reports_list:
                writer.writerow(report)
        print(f"Successfully wrote reports to '{output_file_path}'")
    except IOError as e:
        print(f"Error writing to file '{output_file_path}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred while writing CSV: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Fetches VirusTotal URL reports for a list of URLs from a CSV file."
    )
    parser.add_argument("input_file", help="Path to a CSV file containing URLs (one per line or in the first column).")
    parser.add_argument("--output-file", help="Optional path to a CSV file to save the reports. If not provided, reports will be printed to the terminal.")
    parser.add_argument("--no-header", action="store_true", help="Set if the input CSV file has no header row.")

    args = parser.parse_args()

    api_key = os.environ.get('GTI_APIKEY')
    if not api_key:
        print("Error: GTI_APIKEY environment variable not set. Please set it before running the script.")
        return

    input_path = pathlib.Path(args.input_file)
    if not input_path.is_file():
        print(f"Error: Input file not found at '{input_path}'.")
        return

    urls_to_process = []
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            if not args.no_header:
                try:
                    next(reader) # Skip header row
                except StopIteration:
                    print(f"Warning: Input file '{input_path}' is empty or only contains a header.")
                    return
            for row_num, row in enumerate(reader, 1 if args.no_header else 2):
                if row:
                    url = row[0].strip()
                    if url:
                        urls_to_process.append(url)
                    else:
                        print(f"Warning: Empty URL in input file '{input_path}' at row {row_num}.")
                else:
                    print(f"Warning: Empty row in input file '{input_path}' at row {row_num}.")
    except Exception as e:
        print(f"Error reading input file '{input_path}': {e}")
        return

    if not urls_to_process:
        print(f"No URLs found in input file '{input_path}'.")
        return

    all_reports = []
    for url_count, url_item in enumerate(urls_to_process, 1):
        print(f"\nProcessing URL {url_count}/{len(urls_to_process)}: {url_item}")
        report_json, status_message = get_url_report(api_key, url_item)
        
        extracted_data = extract_url_report_data(url_item, report_json)
        extracted_data["status"] = status_message # Override status with specific API message
        all_reports.append(extracted_data) # Always append to all_reports
        
        if not args.output_file: # Only print to terminal if no output file specified
            print_report_to_terminal(extracted_data)
        else:
            print(f"  Status: {extracted_data['status']}") # Print status summary for CSV mode

    if args.output_file:
        output_path = pathlib.Path(args.output_file)
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        write_reports_to_csv(all_reports, output_path)

    print(f"\nFinished processing all {len(urls_to_process)} URL(s).")

if __name__ == "__main__":
    main()