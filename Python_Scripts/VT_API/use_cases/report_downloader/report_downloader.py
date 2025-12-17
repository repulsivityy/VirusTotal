import os
import requests
import re
import datetime


API_KEY = os.getenv("GTI_APIKEY")
SAVE_DIRECTORY = input("Enter the directory to save reports: ")
SEARCH_QUERY = input("Enter the search query (eg, APT42, Scattered Spider, etc): ")

FILTER_COLLECTION_TYPE = "report"

print("\nSelect Filter Origin:")
print("1. Google Threat Intelligence (default)")
print("2. Crowdsourced")
origin_choice = input("Enter your choice (1 or 2): ").strip()

if origin_choice == "2":
    FILTER_ORIGIN = '"Crowdsourced"'
else:
    FILTER_ORIGIN = '"Google Threat Intelligence"'

date_input = input("Enter creation date filter (number of days, e.g., 7 for 'in the last 7 days'): ").strip()

if not date_input:
    print("No input provided. Defaulting to last 7 days.")
    days_ago = 7
else:
    try:
        days_ago = int(date_input)
    except ValueError:
        print(f"Invalid input '{date_input}'. Defaulting to last 7 days.")
        days_ago = 7

# Calculate the date string
cutoff_date = datetime.date.today() - datetime.timedelta(days=days_ago)
FILTER_CREATION_DATE = f"{cutoff_date.strftime('%Y-%m-%d')}+"
ORDER_BY = "creation_date-"

SEARCH_URL = "https://www.virustotal.com/api/v3/collections"
DOWNLOAD_URL_TEMPLATE = "https://www.virustotal.com/api/v3/collections/{}/download_report"


def get_all_reports(api_key, search_filter, order_by):
    """
    Connects to the VirusTotal API to get a list of all reports matching the filter.
    This function handles pagination automatically to ensure all results are returned.
    """
    print(f"[*] Searching for reports with filter: {search_filter}")
    
    headers = {"x-apikey": api_key, "accept": "application/json"}
    params = {"filter": search_filter, "order": order_by, "limit": 40}
    
    all_reports_found = []
    
    while True:  # This loop will continue until all pages of results are fetched
        try:
            response = requests.get(SEARCH_URL, headers=headers, params=params)
            response.raise_for_status()
            response_json = response.json()
            
            # Add the reports from the current page to our main list
            for report in response_json.get('data', []):
                all_reports_found.append(report)

            # Check if there's a 'next' page of results
            cursor = response_json.get('meta', {}).get('cursor')
            if cursor:
                print("[*] Fetching next page of results...")
                params['cursor'] = cursor  # Set the cursor for the next request
            else:
                break  # No more pages, exit the loop

        except requests.exceptions.HTTPError as http_err:
            print(f"[ERROR] An error occurred: {http_err}\nResponse: {response.text}")
            return []  # Return an empty list on error
            
    print(f"[+] Found a total of {len(all_reports_found)} report(s).")
    return all_reports_found


def main():
    os.makedirs(SAVE_DIRECTORY, exist_ok=True)
    print(f"[*] Reports will be saved in: '{SAVE_DIRECTORY}'")

    print(f"\n--- Processing query: '{SEARCH_QUERY}' ---")
    
    full_filter = (
        f'collection_type:{FILTER_COLLECTION_TYPE} '
        f'name:"{SEARCH_QUERY}" '
        f'creation_date:{FILTER_CREATION_DATE} '
        f'origin:{FILTER_ORIGIN}'
    )
    
    reports_to_download = get_all_reports(API_KEY, full_filter, ORDER_BY)
    
    if not reports_to_download:
        print(f"[*] No reports found for '{SEARCH_QUERY}'. Exiting.")
        return
        
    for report in reports_to_download:
        collection_id = report.get('id')
        report_name = report.get('attributes', {}).get('name', 'Untitled_Report')

        print(f"[*] Downloading: '{report_name}' (ID: {collection_id})")

        get_link_url = DOWNLOAD_URL_TEMPLATE.format(collection_id)
        headers = {"x-apikey": API_KEY, "accept": "application/json"}

        try:
            # First Request: Get the temporary download link
            link_response = requests.get(get_link_url, headers=headers, timeout=30)
            link_response.raise_for_status()
            
            actual_download_url = link_response.json().get('data')

            if not actual_download_url:
                print(f"[ERROR] API did not return a download link for report {collection_id}.")
                continue

            # Second Request: Download the actual PDF from the link
            pdf_response = requests.get(actual_download_url, timeout=60)
            pdf_response.raise_for_status()

            # Verify that the response is actually a PDF before saving.
            if 'application/pdf' not in pdf_response.headers.get('Content-Type', ''):
                print(f"[ERROR] Failed to download a valid PDF for report {collection_id}.")
                print(f"[*] The server returned a non-PDF file. Content-Type: {pdf_response.headers.get('Content-Type')}")
                continue

            # Create a safe filename (remove invalid characters).
            sanitized_name = re.sub(r'[<>:"/\\|?*]', '_', report_name)
            
            # Create the final filename using the required format.
            filename_base = f"{collection_id}_{sanitized_name}"
            
            # Truncate the filename if it's too long and add the .pdf extension.
            final_filename = (filename_base[:200] if len(filename_base) > 200 else filename_base) + ".pdf"
            
            # Create the full path for saving the file.
            file_path = os.path.join(SAVE_DIRECTORY, final_filename)
            
            # Write the downloaded content into the new file.
            with open(file_path, 'wb') as f:
                f.write(pdf_response.content)
            
            print(f"[+] Successfully saved to: {file_path}")

        except requests.exceptions.RequestException as err:
            # This will catch any network-related errors from either request
            print(f"[ERROR] A network error occurred while processing report {collection_id}. Error: {err}")

        print("-" * 20)
        
    print("\n[+] All tasks completed.")


if __name__ == "__main__":
    main()

