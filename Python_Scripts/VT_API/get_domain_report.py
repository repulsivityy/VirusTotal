#####################################
# Usage
# Takes domains as inputs, and checks GTI for the result
# when using the arguments, it will pull the relations and extracts them into a csv file. 
# Currently only using subdomains and urls. will extend to full list
# Domain relations full list here - https://gtidocs.virustotal.com/reference/domains-object

# Usages
# $ python3 get_domain_report.py 
# $ python3 get_domain_report.py --urls --output-file <path-to-dir>

# requirements:
# - Google Threat Intelligence (or VT) API Key

# author: dominicchua@
# version: 1
# USE AT YOUR OWN RISK
#####################################

import requests
import csv
import json # For pretty printing errors if needed
import os   # For accessing environment variables
import argparse # For command-line arguments
import pathlib # For path handling
import concurrent.futures # For concurrency

VT_API_URL_DOMAIN = "https://www.virustotal.com/api/v3/domains/{}"
VT_API_URL_DOMAIN_RELATIONSHIP = "https://www.virustotal.com/api/v3/domains/{}/{}"

RELATIONSHIP_FIELD_MAPPING = {
    "subdomains": ["id", "last_analysis_stats"],
    "urls": ["id", "last_final_url", "last_analysis_stats"],
    # Add other relationship mappings here if you add more CLI flags
    # e.g., "resolutions": ["id", "ip_address_last_analysis_stats", "network"],
}

def get_domain_report(api_key, domain):
    """Fetches the Google Threat Intelligence report for a given domain."""
    headers = {
        "x-apikey": api_key,
        "x-tool": "get_domain_report_script"
    }
    url = VT_API_URL_DOMAIN.format(domain)
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        if response is not None:
            if response.status_code == 401:
                print("Error: Unauthorized. Please check your API key.")
            elif response.status_code == 404:
                print(f"Error: Domain '{domain}' not found on Google Threat Intelligence.")
            else:
                try:
                    error_details = response.json()
                    print(f"API Error details: {json.dumps(error_details, indent=2)}")
                except json.JSONDecodeError:
                    print(f"Could not parse error response from API. Status: {response.status_code}, Body: {response.text}")
    except requests.exceptions.Timeout:
        print(f"Request timed out while fetching report for domain: {domain}")
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}")
    return None

def get_relationship_data(api_key, domain, relationship_name, page_limit=40, total_limit_arg=None): # Max items per page, VT default for relationships is often 40.
    """Fetches a specific relationship for a given domain from its dedicated endpoint, handling pagination."""
    all_items = []
    headers = {
        "x-apikey": api_key,
        "x-tool": "get_domain_report_script_relationship_fetcher"
    }
    
    current_url = VT_API_URL_DOMAIN_RELATIONSHIP.format(domain, relationship_name)
    current_params = {'limit': page_limit}
    
    page_num = 1
    max_pages_to_fetch = 1000 # Safety break for very large result sets
    
    while current_url and page_num <= max_pages_to_fetch:
        # print(f"Fetching page {page_num} for relationship '{relationship_name}' from: {current_url}" + (f" with params {current_params}" if current_params else "")) # Verbose log removed
        try:
            response = requests.get(current_url, headers=headers, params=current_params, timeout=60)
            response.raise_for_status()
            response_data = response.json()

            if page_num == 1 and "meta" in response_data and "count" in response_data["meta"]:
                total_available_items = response_data["meta"]["count"]
                print(f"Total items available for relationship '{relationship_name}': {total_available_items}")

            if "data" in response_data:
                data_list = response_data["data"]
                if isinstance(data_list, list):
                    if total_limit_arg is not None:
                        remaining_capacity = total_limit_arg - len(all_items)
                        if remaining_capacity <= 0: # Already reached or exceeded limit
                            current_url = None # Stop pagination by ensuring loop condition fails
                            break # Exit the while loop immediately
                        items_to_add = data_list[:remaining_capacity]
                        all_items.extend(items_to_add)
                    else: # No total limit, add all from this page
                        all_items.extend(data_list)
                    print(f"  Page {page_num}: Fetched {len(data_list)} items (added {len(items_to_add) if total_limit_arg is not None and 'items_to_add' in locals() else len(data_list)}). Total items so far: {len(all_items)}")
                # Handle non-list data for a paginated endpoint (unusual but defensive)
                elif isinstance(data_list, dict) and page_num == 1 and not (response_data.get('links', {}).get('next') or response_data.get('meta', {}).get('cursor')):
                    all_items.append(data_list) # Single, non-paginated result
                    print(f"  Page {page_num}: Fetched 1 item (non-paginated). Total items so far: {len(all_items)}")
                elif isinstance(data_list, dict): # If data is a dict on a subsequent page or if pagination cues exist
                     print(f"  Warning: Received a dictionary for 'data' on page {page_num} of a paginated request. Item: {data_list}")
                     if "id" in data_list and "type" in data_list: # Attempt to add if it looks like a valid item
                        all_items.append(data_list)
            
            if total_limit_arg is not None and len(all_items) >= total_limit_arg:
                print(f"Reached total limit of {total_limit_arg} items for relationship '{relationship_name}'.")
                current_url = None # Stop pagination
                break # Exit while loop

            # Determine next URL and params for pagination
            next_page_link = response_data.get('links', {}).get('next')
            if next_page_link:
                current_url = next_page_link
                current_params = {} # All params are usually in the 'next' link
            else:
                # Fallback to cursor if 'next' link is missing
                cursor = response_data.get('meta', {}).get('cursor')
                if cursor:
                    current_url = VT_API_URL_DOMAIN_RELATIONSHIP.format(domain, relationship_name) # Reset to base relationship URL
                    current_params = {'limit': page_limit, 'cursor': cursor}
                else:
                    current_url = None # No more pages

            page_num += 1

        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred while fetching page {page_num-1} for relationship '{relationship_name}': {http_err}")
            if response is not None:
                if response.status_code == 401: print("Error: Unauthorized. Please check your API key.")
                elif response.status_code == 404: print(f"Error: Relationship '{relationship_name}' or domain '{domain}' not found (404).")
            # Return what has been fetched so far, or None if nothing was fetched
            return {"data": all_items} if all_items else None
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred while fetching page {page_num-1} for relationship '{relationship_name}': {req_err}")
            return {"data": all_items} if all_items else None
        except json.JSONDecodeError:
            print(f"JSON decode error for page {page_num-1} of '{relationship_name}'. Response: {response.text if response else 'No response'}")
            return {"data": all_items} if all_items else None
            
    if page_num > max_pages_to_fetch:
        print(f"Warning: Reached maximum page fetch limit ({max_pages_to_fetch}) for relationship '{relationship_name}'. Partial data might be returned.")

    if not all_items:
        print(f"No items found for relationship '{relationship_name}' after fetching all pages.")
        return {"data": []} # Return empty list in expected structure
        
    print(f"Fetched a total of {len(all_items)} items over {page_num-1} page(s) for relationship '{relationship_name}'.")
    return {"data": all_items} # Return all aggregated items in the expected structure



def extract_relationship_to_csv(domain, relationship_name, relationship_content, output_dir_path_str):
    """Extracts a specific relationship to a CSV file in the specified output directory."""
    if not relationship_content or "data" not in relationship_content:
        print(f"No data found for relationship '{relationship_name}'.")
        return

    items = relationship_content["data"]

    if not isinstance(items, list):
        if isinstance(items, dict): # Handle single item relationship
            items = [items]
        else:
            print(f"Data for relationship '{relationship_name}' is not in a processable list or dictionary format. Found type: {type(items)}. Skipping.")
            return

    if not items:
        print(f"No items to extract for relationship '{relationship_name}'.")
        return

    desired_fields_for_relationship = RELATIONSHIP_FIELD_MAPPING.get(relationship_name)
    processed_items = []

    for item_idx, item in enumerate(items):
        if isinstance(item, dict):
            row_data = {}
            if desired_fields_for_relationship:
                # Always include 'id' if it's in the mapping or present at the top level
                if "id" in desired_fields_for_relationship or "id" in item:
                    row_data["id"] = item.get("id")

                if "attributes" in item:
                    for field in desired_fields_for_relationship:
                        if field != "id": # 'id' is top-level, already handled
                            # This assumes fields in RELATIONSHIP_FIELD_MAPPING (other than 'id')
                            # are expected to be directly under 'attributes'.
                            # For more complex nesting, this logic would need to be more sophisticated.
                            value = item["attributes"].get(field)
                            if value is not None:
                                row_data[field] = value
            elif "attributes" in item: # Default: take id, type, and all attributes if no specific mapping
                row_data = {"id": item.get("id"), "type": item.get("type")}
                row_data.update(item["attributes"])
            else: # No specific mapping and no 'attributes' key, take the item as is if it has an 'id'
                if "id" in item: # Ensure at least an ID is present for consistency
                    row_data = item

            if row_data: # Ensure we have something to add
                processed_items.append(row_data)
            else:
                # This case should be rare if items always have an 'id' or 'attributes'
                print(f"Item #{item_idx + 1} in relationship '{relationship_name}' resulted in empty row_data. Item: {item}. Skipping.")
        else:
            print(f"Item #{item_idx + 1} in relationship '{relationship_name}' is not a dictionary (type: {type(item)}). Value: '{item}'. Skipping this item.")
            continue
    
    if not processed_items:
        print(f"No processable items found for relationship '{relationship_name}'.")
        return

    # Use the output directory from argparse (stored in args by main function)
    # Ensure the directory exists
    output_dir = pathlib.Path(output_dir_path_str)
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = output_dir / f"{domain}_{relationship_name}.csv"
    
    all_keys = set()
    for item_data in processed_items:
        if isinstance(item_data, dict):
            all_keys.update(item_data.keys())
    
    fieldnames = sorted(list(all_keys))
    if not fieldnames: # Should not happen if processed_items is not empty and contains dicts
        print(f"Could not determine headers for CSV for relationship '{relationship_name}'. Skipping.")
        return

    try:
        with open(filename, "w", newline="", encoding="utf-8") as csvfile: # Use pathlib Path object directly
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for item_data in processed_items:
                if isinstance(item_data, dict):
                    row_to_write = {key: item_data.get(key, "") for key in fieldnames}
                    writer.writerow(row_to_write)
                # else: item was already skipped or processed_items wouldn't contain it
        print(f"Successfully extracted '{relationship_name}' to '{filename}'")
    except IOError:
        print(f"Error writing to file '{filename}'. Check permissions or disk space.")
    except Exception as e:
        print(f"An unexpected error occurred while writing CSV for '{relationship_name}': {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Takes a domain as input and checks Google Threat Intelligence (or VT) for the result. "
                    "If specific relationship arguments (e.g., --subdomains) are used, "
                    "it will pull those relationships and extract them into CSV files. "
                    "Otherwise, it displays a summary of the main domain report.")
    parser.add_argument("domain", help="The domain to analyze (e.g., example.com).")
    parser.add_argument("--subdomains", action="store_true", help="Fetch and export subdomains to CSV.")
    parser.add_argument("--urls", action="store_true", help="Fetch and export URLs associated with the domain to CSV.")
    # Add more relationship flags here as needed, e.g., --resolutions, --urls
    parser.add_argument("--output-dir", default=".", help="Directory to save output CSV files. Defaults to current directory.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of items to fetch for each specified relationship.")


    args = parser.parse_args()

    api_key = os.environ.get('GTI_APIKEY')
    if not api_key:
        print("Error: GTI_APIKEY environment variable not set. Please set it before running the script.")
        return

    domain = args.domain.strip()
    if not domain:
        print("Error: Domain argument cannot be empty.")
        return

    possible_relationships_map = {
        "subdomains": args.subdomains,
        "urls": args.urls,
        # "resolutions": args.resolutions, # Example: Add new args here
    }
    relationships_to_fetch_args = [rel_name for rel_name, requested in possible_relationships_map.items() if requested]
    specific_relationship_requested = bool(relationships_to_fetch_args)

    if specific_relationship_requested:
        fetched_data = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor: # Adjust max_workers as needed
            future_to_rel = {
                executor.submit(get_relationship_data, api_key, domain, rel_name, total_limit_arg=args.limit): rel_name 
                for rel_name in relationships_to_fetch_args
            }
            for future in concurrent.futures.as_completed(future_to_rel):
                rel_name = future_to_rel[future]
                try:
                    data = future.result()
                    if data:
                        fetched_data[rel_name] = data
                        print(f"Successfully fetched data for relationship: {rel_name}")
                except Exception as exc:
                    print(f"Relationship '{rel_name}' generated an exception during fetch: {exc}")

        # Process and extract fetched data sequentially after all futures are complete
        for rel_name, data_content in fetched_data.items():
            print(f"\n--- Extracting {rel_name} for {domain} ---")
            extract_relationship_to_csv(domain, rel_name, data_content, args.output_dir)

        print("\nFinished processing specified relationships.")
    else:
        # If no specific relationship flags were used, fetch and display the main domain report summary.
        print(f"\nFetching main report for domain: {domain}...")
        report_data = get_domain_report(api_key, domain)

        if not report_data or "data" not in report_data or "attributes" not in report_data["data"]:
            print("Failed to retrieve or parse valid main report data.")
            return

        print("\n--- Domain Report Summary ---")
        attributes = report_data["data"]["attributes"]
        print(f"Domain: {domain}")
        print(f"Last Analysis Stats: {attributes.get('last_analysis_stats')}")
        print(f"Reputation: {attributes.get('reputation')}")

if __name__ == "__main__":
    main()
    