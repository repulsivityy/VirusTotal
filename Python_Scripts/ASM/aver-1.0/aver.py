__created__ = "Sept 26, 2025"
__updated__ = "Nov 6, 2025"
__version__ = "1.0"
__note__ = "You may not use this script except in compliance with the LICENSE.txt file provided with this script."

import platform
import warnings

# Check if the system is macOS and suppress specific warnings
if platform.system() == "Darwin":
    warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

import os
import sys
import json
import pandas as pd
from pathlib import Path
from getpass import getpass
import io
import logging
import time
from time import strftime # <-- ADDED THIS IMPORT
import requests
import argparse
import threading
import itertools
import traceback
import re # Was missing from top-level imports, needed for regex_file()
from requests.auth import HTTPBasicAuth
from jinja2 import Environment, FileSystemLoader
from concurrent.futures import ThreadPoolExecutor
import signal
import http.client
import shutil

# --- Asynchronous Operations ---
import asyncio
import aiohttp
import ssl # ADDED FOR SSL CONTROL
from concurrent.futures import ThreadPoolExecutor as AsyncThreadPoolExecutor
from tqdm.asyncio import tqdm
import logging

from urllib.parse import quote

class TqdmLoggingHandler(logging.Handler):
    """Redirects logging to tqdm.write() to prevent progress bar corruption."""
    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handleError(record)

# --- GCP Integration (Conditional Import) ---
try:
    from google.cloud import storage
    from google.api_core.exceptions import GoogleAPICallError
    GCP_ENABLED = True
except ImportError:
    GCP_ENABLED = False

# --- Constants ---
# API endpoints for ASM Data Export
VT_ASM_URL_BASE = "https://www.virustotal.com/api/v3/asm/"
ADV_ASM_URL_BASE = "https://asm-api.advantage.mandiant.com/api/v1/"
ASM_URL_BASE = VT_ASM_URL_BASE  # Default, will be updated dynamically

# API endpoints for CVE Vulnerability Lookup
ADV_MATI_BASE_URL = "https://api.intelligence.mandiant.com/v4/vulnerability"
MANDIANT_TOKEN_URL = "https://api.intelligence.mandiant.com/token"

# ASM Endpoint Names
PROJECTS_ENDPOINT = "projects"
COLLECTIONS_ENDPOINT = "user_collections/"
ENTITIES_ENDPOINT = "search/entities"
ISSUES_ENDPOINT = "search/issues/"
TECHNOLOGIES_ENDPOINT = "search/technologies/"

# Credential File Names
CREDENTIALS_FILE = "googleti-api-credentials.json"
ADV_ASM_CREDENTIALS_FILE = "adv-asm-api-credentials.json"
MATI_CREDENTIALS_FILE = "mati-api-credentials.json"


# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Setup globals ---
global_scan_filters = {}

# --- Start of new debug code ---
http.client.HTTPConnection.debuglevel = 0
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
# --- End of debug code ---

def display_disclaimer():
    """Displays a standard disclaimer."""
    disclaimer = """
    ================================================================================
    DISCLAIMER
    ================================================================================
    This script is provided "as-is" without any warranties or guarantees of any kind.
    By using this script, you acknowledge and agree to the terms of this disclaimer.
    ================================================================================
    """
    print(disclaimer)

def print_usage():
    """Prints usage information."""
    print("Usage: python asmExportReport.py [options]")
    print("\nThis script runs a multi-step automated workflow:")
    print("  1. Exports entities, issues, or technologies from a selected")
    print("     Google Threat Intelligence or Mandiant Advantage ASM project.")
    print("  2. If issues were exported, it fetches full details for each issue.")
    print("  3. Asks the user if a CVE vulnerability report should be generated.")
    print("  4. If yes, it generates a detailed HTML vulnerability report using the Mandiant Intelligence API.")
    print("  5. Asks the user if the entire project folder should be uploaded to GCP.")
    print("\nOptions:")
    print("  -key              Prompt for the Google TI API key (overrides saved credentials).")
    print("  -adv              Use Mandiant Advantage ASM endpoints and authentication for the initial data export.")
    print("  -concurrency N    Set max concurrent connections for issue details (default: 100).")
    print("  -nobanner         Hide the disclaimer banner.")
    print("  -debug            Enable detailed debug logging.")
    print("  -noverify         Disable SSL certificate verification (use with caution).")
    print("  -h, --help        Show this help message.")


def load_credentials():
    """Loads Google TI API credentials from a file or prompts the user."""
    if "-key" in sys.argv:
        # Use getpass to securely prompt for the key
        googleti_api_key = getpass("Enter Google Threat Intelligence API key: ")
        return googleti_api_key

    home_dir = Path.home()
    credentials_path = home_dir / ".api-credentials" / CREDENTIALS_FILE
    credentials_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(credentials_path, 'r') as f:
            return json.load(f)['googleti_api_key']
    except FileNotFoundError:
        print("Google Threat Intelligence credentials file not found.")
        googleti_api_key = getpass("Enter Google Threat Intelligence API key: ")
        with open(credentials_path, "w") as f:
            json.dump({'googleti_api_key': googleti_api_key}, f)
        return googleti_api_key
    except (KeyError, json.JSONDecodeError):
         raise SystemExit(f"Error: Could not read 'googleti_api_key' from {credentials_path}. Please check the file format.")

def get_yes_no(prompt):
    """Prompts the user for a yes/no answer."""
    while True:
        choice = input(f"{prompt} (yes/no): ").lower().strip()
        if choice in ['yes', 'y']:
            return True
        elif choice in ['no', 'n']:
            return False
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

def load_adv_asm_credentials(debug):
    """Loads Mandiant Advantage ASM API credentials from a specified file."""
    home_dir = Path.home()
    credentials_folder = home_dir / ".api-credentials"
    credentials_path = credentials_folder / ADV_ASM_CREDENTIALS_FILE
    credentials_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(credentials_path, 'r') as f:
            creds = json.load(f)
            access_key = creds['access_key']
            secret_key = creds['secret_key']

    except FileNotFoundError:
        print(f"Mandiant Advantage ASM credentials file not found at '{credentials_path}'.")
        if get_yes_no("Would you like to create it now?"):
            access_key = getpass("Enter Mandiant Advantage ASM API Access Key: ")
            secret_key = getpass("Enter Mandiant Advantage ASM API Secret Key: ")

            api_credentials = {
                'access_key': access_key,
                'secret_key': secret_key
            }
            with open(credentials_path, "w") as f:
                json.dump(api_credentials, f)
        else:
            raise SystemExit("Mandiant Advantage ASM API credentials are required. Exiting.")
    except (KeyError, json.JSONDecodeError):
        raise SystemExit(f"Error: Could not read 'access_key' or 'secret_key' from {credentials_path}. Please check the file format.")

    headers = {"INTRIGUE_ACCESS_KEY": access_key, "INTRIGUE_SECRET_KEY": secret_key}

    return headers

def load_mati_credentials():
    """Loads Mandiant Intelligence (MATI) API credentials from a file."""
    home_dir = Path.home()
    credentials_folder = home_dir / ".api-credentials"
    credentials_path = credentials_folder / MATI_CREDENTIALS_FILE
    credentials_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(credentials_path, 'r') as f:
            creds = json.load(f)
            return creds['mati_access_key'], creds['mati_secret_key']
    except FileNotFoundError:
        print(f"Mandiant Intelligence credentials file not found at '{credentials_path}'.")
        if get_yes_no("Would you like to create it now?"):
            access_key = getpass("Enter MATI API Access Key: ")
            secret_key = getpass("Enter MATI API Secret Key: ")

            api_credentials = {
                'mati_access_key': access_key,
                'mati_secret_key': secret_key
            }
            with open(credentials_path, "w") as f:
                json.dump(api_credentials, f)
            return access_key, secret_key
        else:
            raise SystemExit("Mandiant Intelligence API credentials are required. Exiting.")
    except (KeyError, json.JSONDecodeError):
        raise SystemExit(f"Error: Could not read keys from {credentials_path}. Please check the file format.")


def select_export_type():
    """Prompts the user to select the type of data to export."""
    print("\nWhat data would you like to export from the selected collection(s)?")
    print("\t 1. Entities")
    print("\t 2. Issues")
    print("\t 3. Technologies")
    print("\t 4. All (Entities, Issues, and Technologies) - Asynchronously")
    print("\n\t q. Cancel and Exit")

    while True:
        user_input = input("\nEnter the number of your choice (or 'q' to quit): ").strip().lower()

        if user_input == 'q':
            print("\nCancel requested. Exiting.")
            sys.exit(0)

        try:
            choice = int(user_input)
            if choice in [1, 2, 3, 4]:
                return {1: "entities", 2: "issues", 3: "technologies", 4: "all"}[choice]
            else:
                print("Invalid choice. Please enter 1, 2, 3, 4, or q.")
        except ValueError:
            print("Invalid input. Please enter a number or 'q'.")

async def select_output_destination_async():
    """Prompts user to select the output destination."""
    print("\nWhere would you like to store the results?")
    print("\t 1. Local Directory (in the same folder as the script)")
    print("\t 2. GCP Cloud Storage Bucket")
    print("\n\t q. Cancel and Exit")

    if not GCP_ENABLED:
        print("\nNote: GCP Cloud Storage library not found. To use the GCP feature,")
        print("please install it by running: pip install google-cloud-storage")
        print("Defaulting to Local Directory.")
        return "local", None

    while True:
        user_input = input("\nEnter the number of your choice (or 'q' to quit): ").strip().lower()
        
        if user_input == 'q':
            print("\nCancel requested. Exiting.")
            sys.exit(0)

        try:
            choice = int(user_input)
            if choice == 1:
                return "local", None
            elif choice == 2:
                bucket_name = select_gcp_bucket_interactive()
                if bucket_name:
                     return "gcp", bucket_name
                else:
                     print("No bucket selected. Returning to menu.")
                     continue
            else:
                print("Invalid choice. Please enter 1, 2, or q.")
        except ValueError:
            print("Invalid input. Please enter a number or 'q'.")

async def get_project_id(session, debug):
    """Fetches projects and prompts for selection asynchronously."""
    print("\nFetching projects...")
    try:
        async with session.get(ASM_URL_BASE + PROJECTS_ENDPOINT) as projects_response:
            projects_response.raise_for_status()
            response_json = await projects_response.json()

            if debug:
                print("\n--- Debug: Raw JSON Response for Projects ---")
                print(json.dumps(response_json, indent=2))
                print("-------------------------------------------\n")

    except aiohttp.ClientError as e:
        print(f"Error retrieving projects: {e}")
        return None, None
    
    projects_data = response_json.get('result', [])
    if not projects_data:
        print("No projects found for this API key.")
        return None, None

    print("\nAvailable Projects To Select From:")
    for index, project in enumerate(projects_data):
        print(f"\t {index + 1}. {project.get('name', 'Unnamed Project')}")
    print("\n\t q. Cancel and Exit")
    
    while True:
        user_input = input("\nEnter the number of the project (or 'q' to quit): ").strip().lower()
        
        if user_input == 'q':
            print("\nCancel requested. Exiting.")
            sys.exit(0)
            
        try:
            choice = int(user_input) - 1
            if 0 <= choice < len(projects_data):
                selected_project = projects_data[choice]
                return selected_project['id'], selected_project['name']
            else:
                print("Invalid choice. Please enter a number from the list or 'q'.")
        except ValueError:
            print("Invalid input. Please enter a number or 'q'.")

async def select_collections_to_process(session, debug):
    """
    Fetches collections, filters for active ones with valid scan data,
    and prompts user to select one or all.
    """
    print(f"\nFetching collections for the selected project...")
    try:
        async with session.get(ASM_URL_BASE + COLLECTIONS_ENDPOINT) as collections_response:
            collections_response.raise_for_status()
            response_json = await collections_response.json()

            if debug:
                print("\n--- Debug: Raw JSON Response for Collections ---")
                print(json.dumps(response_json, indent=2))
                print("----------------------------------------------\n")
    except aiohttp.ClientError as e:
        print(f"Error retrieving collections: {e}")
        return None
    
    all_collections = response_json.get('result', [])
    if not all_collections:
        print("No collections found in this project.")
        return None

    selectable_collections = []
    skipped_collections = []

    # Filter collections: must not be deleted AND must have a valid scan count
    for collection in all_collections:
        if not collection.get('deleted'):
            collection_name = collection.get('printable_name', collection.get('name', 'Unnamed Collection'))
            # Use the safe (fixed) method to get scan count
            scan_count = (collection.get('config') or {}).get('custom_last_refreshes_count', 'N/A')
            
            if scan_count != 'N/A' and scan_count is not None:
                # This collection is valid; add it to the menu list
                selectable_collections.append({
                    "data": collection,
                    "name": collection_name,
                    "scan_count": scan_count
                })
            else:
                # Collection is skipped due to no data
                skipped_collections.append(collection_name)
        else:
            # Collection is skipped because it's deleted
            skipped_collections.append(f"{collection.get('name', 'Unknown')} (Deleted)")


    if not selectable_collections:
        print("\nNo active collections with available scan data were found.")
        if skipped_collections:
            print("The following collections were skipped:")
            for name in skipped_collections:
                print(f"\t- {name}")
        return None

    # Build the menu only from the valid, selectable collections
    print("\nAvailable Collections To Select From (collections with no scan data are hidden):")
    print(f"\t 0. All Selectable Collections ({len(selectable_collections)} collections)")
    for index, item in enumerate(selectable_collections):
        print(f"\t {index + 1}. {item['name']} (Last Scan Count: {item['scan_count']})")
    print("\n\t q. Cancel and Exit")

    if skipped_collections:
        print("\nNote: The following collections were skipped (deleted or no scan data):")
        for name in skipped_collections:
            print(f"\t- {name}")

    while True:
        user_input = input("\nEnter the number of the collection (or 0 for All, 'q' to quit): ").strip().lower()
        
        if user_input == 'q':
            print("\nCancel requested. Exiting.")
            sys.exit(0)
            
        try:
            choice = int(user_input)
            if choice == 0:
                # Return the list of all *valid* collection data objects
                return [item['data'] for item in selectable_collections]
            elif 1 <= choice <= len(selectable_collections):
                # Return the single selected *valid* collection data object in a list
                return [selectable_collections[choice - 1]['data']]
            else:
                print("Invalid choice. Please enter a number from the list, 0, or 'q'.")
        except ValueError:
            print("Invalid input. Please enter a number or 'q'.")

async def get_paginated_data(session, base_query_url, debug, blob_name, data_type_name, printable_collection_name):
    """
    Fetches paginated data and returns it in an in-memory CSV buffer, showing progress.
    """
    all_hits = []
    next_page_url = base_query_url

    with tqdm(desc=f"Fetching {data_type_name} from '{printable_collection_name}'", unit=" items") as pbar:
        while next_page_url:
            if debug:
                logger.debug(f"Debug ({printable_collection_name}): Requesting URL: {next_page_url}")

            try:
                async with session.get(next_page_url) as response:
                    response.raise_for_status()
                    data = await response.json()
            except (aiohttp.ClientError, json.JSONDecodeError) as e:
                tqdm.write(f"[!] Error fetching data for {data_type_name} from '{printable_collection_name}': {e}")
                break

            hits_on_page = data.get('result', {}).get('hits', [])

            if not hits_on_page:
                break

            all_hits.extend(hits_on_page)
            pbar.update(len(hits_on_page))

            next_page_token = data.get('result', {}).get('next_page_token')
            if next_page_token:
                next_page_url = f"{base_query_url}&page_token={next_page_token}"
            else:
                break

    csv_buffer = None
    total_count = len(all_hits)
    if all_hits:
        pbar.set_description(f"Fetched {total_count} {data_type_name} from '{printable_collection_name}'")
        try:
            df = pd.DataFrame(all_hits)
            csv_buffer = io.StringIO()
            df.to_csv(csv_buffer, index=False)
        except Exception as e:
            tqdm.write(f"[!] Error creating CSV buffer for {blob_name}: {e}")
            return total_count, data_type_name, blob_name, printable_collection_name, None

    return total_count, data_type_name, blob_name, printable_collection_name, csv_buffer

def select_gcp_bucket_interactive():
    """
    Lists available GCS buckets for the authenticated project and prompts 
    the user to select one by index.
    """
    if not GCP_ENABLED:
         print("\nGCP support is not enabled (missing google-cloud-storage library).")
         return None

    print("\nAUTHENTICATION CHECK: Ensure you have run 'gcloud auth application-default login'")
    print("Fetching available GCP Cloud Storage buckets...")
    
    try:
        # Initialize client and fetch buckets
        storage_client = storage.Client()
        buckets = list(storage_client.list_buckets())
        
        if not buckets:
            print("No buckets found in the currently authenticated GCP project.")
            return None

        print("\nAvailable GCP Buckets:")
        for i, bucket in enumerate(buckets):
            print(f"\t {i + 1}. {bucket.name}")
        print("\n\t q. Cancel selection")

        while True:
            choice = input("\nSelect a bucket by number (or 'q' to cancel): ").strip().lower()
            if choice == 'q':
                return None
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(buckets):
                    selected_bucket_name = buckets[idx].name
                    print(f"Selected bucket: '{selected_bucket_name}'")
                    return selected_bucket_name
                else:
                     print(f"Invalid selection. Please enter a number between 1 and {len(buckets)}.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    except Exception as e:
        print(f"\n❌ Error fetching buckets: {e}")
        print("Please check your GCP authentication and project permissions.")
        return None

def upload_file_to_gcs(bucket, source_file_path, destination_blob_name):
    """Uploads a file to a GCS bucket (blocking) using a pre-initialized bucket object."""
    try:
        blob = bucket.blob(destination_blob_name)
        blob.upload_from_filename(source_file_path)
        return destination_blob_name, True, None
    except Exception as e:
        return destination_blob_name, False, str(e)

async def async_upload_file(pool, bucket, source_file_path, destination_blob_name):
    """Async wrapper for upload_file_to_gcs using a *shared* ThreadPoolExecutor."""
    loop = asyncio.get_running_loop()
    blob_name, success, error_msg = await loop.run_in_executor(
        pool, 
        upload_file_to_gcs, 
        bucket,
        source_file_path, 
        destination_blob_name
    )
    return blob_name, success, error_msg

async def main(noverify=False):
    """
    Main asynchronous workflow for ASM data export.
    Returns a tuple of (created_filenames_list, project_id, debug_status, project_dir_name, base_headers).
    """
    global ASM_URL_BASE
    if "-h" in sys.argv or "--help" in sys.argv:
        print_usage()
        sys.exit(0)
    if "-nobanner" not in sys.argv:
        display_disclaimer()

    advantage_mode = "-adv" in sys.argv
    debug = "-debug" in sys.argv
    
    if advantage_mode:
        print("\n--- Running in Mandiant Advantage Mode ---")
        ASM_URL_BASE = ADV_ASM_URL_BASE
        try:
            base_headers = load_adv_asm_credentials(debug)
        except SystemExit as e:
            print(e)
            sys.exit(1)
    else:
        print("\n--- Running in Google Threat Intelligence (VirusTotal) Mode ---")
        ASM_URL_BASE = VT_ASM_URL_BASE
        try:
            googleti_api_key = load_credentials()
            base_headers = {"X-Apikey": f"{googleti_api_key}"}
        except SystemExit as e:
            print(e)
            sys.exit(1)
            
    if debug:
        print(f"[DEBUG] Initializing API session with headers: {redact_api_key_from_headers(base_headers)}")

    connector = aiohttp.TCPConnector(ssl=False if noverify else None)
    async with aiohttp.ClientSession(headers=base_headers, connector=connector) as session:
        project_id, project_name = await get_project_id(session, debug)
        if not project_id:
            print("\nNo project was selected. Exiting.")
            return [], None, debug, None, None, None
        print(f"\nProject '{project_name}' selected.")
        session.headers.update({'PROJECT-ID': str(project_id)})

        project_dir_name = "".join(c for c in project_name if c.isalnum() or c in (' ', '_')).rstrip().replace(' ', '_')
        project_path = Path(project_dir_name)
        project_path.mkdir(exist_ok=True)
        print(f"All outputs will be saved locally under the project folder: '{project_dir_name}'")

        collections_to_process = await select_collections_to_process(session, debug)
        if not collections_to_process:
            print("\nNo collection(s) were selected. Exiting.")
            return [], project_id, project_name, debug, project_dir_name, base_headers
        
        export_type = select_export_type()
        
        print("-" * 50)
        fetch_tasks = []
        endpoints = {"entities": ENTITIES_ENDPOINT, "issues": ISSUES_ENDPOINT, "technologies": TECHNOLOGIES_ENDPOINT}
        data_types_to_fetch = endpoints.keys() if export_type == 'all' else [export_type]

        for collection in collections_to_process:
            printable_name = collection.get('printable_name', collection['name'])
            collection_dir_name = "".join(c for c in printable_name if c.isalnum() or c in (' ', '_')).rstrip().replace(' ', '_')
            
            collection_path = project_path / collection_dir_name
            collection_path.mkdir(exist_ok=True) 

            csv_output_dir = collection_path / "csv"
            csv_output_dir.mkdir(exist_ok=True)

            for data_type in data_types_to_fetch:
                file_basename = f"{collection_dir_name}_{data_type}_{project_id}.csv"
                full_file_path = str(csv_output_dir / file_basename)

                search_string = f"collection:{collection['name']}"

                if data_type == 'issues':
                    default_scan_count = collection.get('config', {}).get('custom_last_refreshes_count')
                    prompt_msg = f"\nFilter issues for '{printable_name}'.\n"
                    if default_scan_count is not None:
                        prompt_msg += f"Press Enter to use the default scan count ({default_scan_count}), or enter a number (1-10): "
                    else:
                        prompt_msg += "Enter a scan count number (1-10) to filter by: "

                    while True:
                        try:
                            user_input = input(prompt_msg).strip()
                            if not user_input and default_scan_count is not None:
                                n = default_scan_count
                                break
                            
                            n = int(user_input)
                            if 1 <= n <= 10:
                                break
                            else:
                                print("Error: Please enter a number between 1 and 10.")
                        except ValueError:
                            print("Error: Invalid input. Please enter a number.")
                    
                    scan_count_filter = f" last_seen_after:last_scan_count_{n}"
                    search_string += scan_count_filter
                    print(f"Applying filter: '{scan_count_filter.strip()}'")

                    # Store all metadata for the report, not just the scan filter
                    global_scan_filters[full_file_path] = {
                        "scan_info": f"Last {n} Scans",
                        "collection_name": printable_name, # <-- Store the clean name
                        "data_type": data_type             # <-- Store the data type
                    }

                encoded_search_string = quote(search_string)
                base_url = f"{ASM_URL_BASE}{endpoints[data_type]}/{encoded_search_string}?page_size=1000"

                task = get_paginated_data(session, base_url, debug, full_file_path, data_type, printable_name)
                fetch_tasks.append(task)
        
        fetch_results = []
        if fetch_tasks:
            print(f"\nStarting {len(fetch_tasks)} data export task(s)...")
            root_logger = logging.getLogger()
            original_handlers = root_logger.handlers[:]
            root_logger.handlers = [TqdmLoggingHandler()]
            fetch_results = await asyncio.gather(*fetch_tasks)
            root_logger.handlers = original_handlers

        output_summary = {}
        created_files = []

        print("\nWriting results to local files...")
        for _, data_type, filename, coll_name, csv_buffer in fetch_results:
            if coll_name not in output_summary: output_summary[coll_name] = []
            if csv_buffer:
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        csv_buffer.seek(0)
                        f.write(csv_buffer.getvalue())
                    output_summary[coll_name].append(f"  - ✅ Success: Saved {data_type} to '{filename}'")
                    created_files.append(filename)
                except IOError as e:
                    output_summary[coll_name].append(f"  - ❌ Error: Failed to write {data_type} to '{filename}': {e}")
            else:
                output_summary[coll_name].append(f"  - ℹ️ No data found for {data_type}.")

        print("\n" + "="*50)
        print("                  Export Summary")
        print("="*50)
        for collection_name, messages in sorted(output_summary.items()):
            print(f"\nCollection: '{collection_name}'")
            for msg in messages:
                print(msg)
        print("\n" + "="*50)
        
        return created_files, project_id, project_name, debug, project_dir_name, base_headers

# ==============================================================================
# ===== START OF CVE VULNERABILITY LOOKUP (MODIFIED FOR MATI API) ==============
# ==============================================================================

# Global variables for the CVE lookup script
mati_bearer_token = None # Global cache for the MATI auth token
exit_event = threading.Event()
template = None
# MODIFIED: These are now passed into the signal handler
# logo_filename = "" 
# base_vuln_url = ""

def get_mati_token(debug=False):
    """
    Fetches a MATI bearer token using client credentials flow.
    Caches the token for the duration of the script run.
    """
    global mati_bearer_token
    if mati_bearer_token:
        if debug:
            print("[DEBUG] Using cached MATI bearer token.")
        return mati_bearer_token

    print("\nAuthenticating to Mandiant Intelligence API for CVE lookup...")
    try:
        client_id, client_secret = load_mati_credentials()
    except SystemExit as e:
        print(e)
        sys.exit(1)

    auth = HTTPBasicAuth(client_id, client_secret)
    headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
    data = {'grant_type': 'client_credentials', 'scope': ''}

    try:
        response = requests.post(MANDIANT_TOKEN_URL, auth=auth, headers=headers, data=data, verify=("-noverify" not in sys.argv))
        response.raise_for_status()
        token_data = response.json()
        mati_bearer_token = token_data['access_token']
        print("✅ Successfully obtained Mandiant Intelligence API token.")
        return mati_bearer_token
    except requests.exceptions.HTTPError as e:
        print(f"❌ Error getting MATI token: {e.response.status_code} {e.response.reason}")
        if e.response.status_code == 401:
            print("-> Unauthorized. Please check your MATI credentials in the {} file.".format(MATI_CREDENTIALS_FILE))
        sys.exit(1)
    except Exception as e:
        print(f"❌ An unexpected error occurred during MATI authentication: {e}")
        sys.exit(1)

# MODIFIED: Refactored to accept local state
def show_progress(output, failed, unknown_len, input_length):
        progress_chars = itertools.cycle(['|', '/', '-', '\\'])
        while not exit_event.is_set():
            part_completed = len(output) + len(failed) + unknown_len
            total = input_length if input_length > 0 else 1 # Avoid division by zero
            percents = round(100.0 * part_completed / float(total), 1)
            
            char = next(progress_chars)
            sys.stdout.write(f'\rProcessing... {percents}% completed... {len(failed)} failed, {unknown_len} unknown and {len(output)} successful... {char}')
            sys.stdout.flush()
            time.sleep(0.2)
        
        sys.stdout.write('\r' + ' ' * 80 + '\r') # Clear the line
        sys.stdout.flush()

# MODIFIED: Refactored to accept local state
def signal_handler(signum, frame, output_path_base, need_csv, output, template, logo_filename, base_vuln_url, debug=False):
        if debug:
            print("\n--- DEBUG: Signal Handler Activated ---")
            print(f"  - Signal Number: {signum}")
            print(f"  - Output Path Base: {output_path_base}")
            print(f"  - CSV Needed: {need_csv}")
            print(f"  - Output Data Items Collected: {len(output)}")
            print(f"  - Template Object Present: {template is not None}")
            print(f"  - Logo Filename: {logo_filename}")
            print(f"  - Base Vuln URL: {base_vuln_url}")
            print("---------------------------------------\n")
        print('\nCtrl+C detected. Writing partial report...')
        output_filename = f"{output_path_base}_cve_report_partial"
        if template:
            logo_path = f"static/images/{logo_filename}"
            with open(output_filename + '.html', 'w', encoding='utf-8') as static_content:
                    static_content.write(template.render(cve_data=output, logo_file_path=logo_path, base_vuln_url=base_vuln_url))
        if need_csv:
                write_csv(output_filename, output)
        logging.info(f"Partial output file {output_filename + '.html'} written!")
        exit_event.set()
        sys.exit(0)

# MODIFIED: Refactored to accept local state
def signal_handler_old(signum, frame, output_path_base, need_csv, output, template, logo_filename, base_vuln_url):
        print('\nCtrl+C detected. Writing partial report...')
        output_filename = f"{output_path_base}_cve_report_partial"
        if template:
            logo_path = f"static/images/{logo_filename}"
            with open(output_filename + '.html', 'w', encoding='utf-8') as static_content:
                    static_content.write(template.render(cve_data=output, logo_file_path=logo_path, base_vuln_url=base_vuln_url))
        if need_csv:
                write_csv(output_filename, output)
        logging.info(f"Partial output file {output_filename + '.html'} written!")
        exit_event.set()
        sys.exit(0)

def load_template(debug=False):
    """Loads the Jinja2 template from the templates directory."""
    global template
    template_dir = Path("templates")
    template_file = template_dir / "aver_output.html"
            
    if debug:
        # Use .resolve() to get the full, unambiguous path for debugging
        print(f"[DEBUG] Attempting to load template from absolute path: {template_file.resolve()}")
            
    if not template_file.is_file():
        # Using .resolve() in the error message also makes it much clearer
        print(f"❌ ERROR: Report template not found at '{template_file.resolve()}'")
        print("Please ensure you have a 'templates/aver_output.html' file relative to your script.")
        raise SystemExit("Exiting due to missing template.")
        
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("aver_output.html")

def build_cve_context_from_json_files(directory, debug):
    """
    Scans the 'issuesDetail' subdirectory for .json files, finds CVEs within them,
    and builds a map from each CVE to its issue context (entity, severity, confidence).
    """
    cve_map = {}
    
    issues_detail_dir = Path(directory) / "issuesDetail"
    if not issues_detail_dir.is_dir():
        logger.warning(f"Could not find the 'issuesDetail' directory in '{directory}'.")
        logger.warning("CVE report will not contain issue context (severity, confidence, entity).")
        return cve_map

    json_files = list(issues_detail_dir.glob('*.json'))
    if not json_files:
        return cve_map

    logger.info(f"Found {len(json_files)} issue detail JSON files to scan for CVE context.")
    
    if debug:
        print("\n--- STARTING JSON FILE DEBUGGING ---")
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if debug:
                print(f"\n[DEBUG] Processing file: {json_file.name}")

            source_obj = data.get('result', data)
            context = {
                "IssueName" : source_obj.get('pretty_name', 'N/A'),
                "IssueUID" : source_obj.get('uid'),
                "EntityName": source_obj.get('entity_name', 'N/A'),
                "EntityUID": source_obj.get('entity_uid'),
                "IssueSeverity": source_obj.get('summary', {}).get('severity', source_obj.get('severity', 'N/A')),
                "IssueConfidence": source_obj.get('summary', {}).get('confidence', source_obj.get('confidence', 'N/A'))
            }

            content_str = json.dumps(data)
            found_cves = re.findall(r'(?i)CVE-\d{4}-\d{4,7}', content_str)

            for cve in set(cve.upper() for cve in found_cves):
                if cve not in cve_map:
                    cve_map[cve] = []
                if context not in cve_map[cve]:
                    cve_map[cve].append(context)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Could not read or parse {json_file}: {e}")
    
    if debug:
        print("\n--- FINISHED JSON FILE DEBUGGING ---\n")
            
    return cve_map

def regex_file(vulnfile):
        try:
                with open(vulnfile, 'r', encoding='utf-8') as vuln:
                        cveRaw = vuln.read()
                vulns = re.findall(r'(?i)CVE-\d{4}-\d{4,7}', cveRaw)
                return sorted(list(set(cve.upper() for cve in vulns)))
        except Exception as e:
                raise Exception(f"Could not read the file '{vulnfile}', {e}")

def replace_chars(data):
        return data.replace('<', '&lt;').replace('>', '&gt;')

def trim_date_part(input_date):
        return input_date.split('T', 1)[0] if input_date else ""

def divide_chunks(input_list, size):
        for x in range(0, len(input_list), size):
                yield input_list[x:x+size]

def diff_list(cves_p, cves_resp):
        return list(filter(lambda x: x not in cves_resp, cves_p))

def post_vuln_lookup(cves_p, headers, cve_context_map, noverify=False, debug=False):
    """
    Worker function for ThreadPoolExecutor. Fetches vulnerability data.
    Returns a tuple: (list_of_success_data, list_of_failed_cves, list_of_unknown_cves)
    """
    output_arr = []
    cves_with_resp = []
    session = requests.Session()

    try:
        payload = {"requests": [{"values": cves_p}]}
        url = ADV_MATI_BASE_URL
        
        with session.post(url, headers=headers, json=payload, verify=not noverify) as resp:
            if debug:
                print("\n--- CVE LOOKUP DEBUG ---")
                print(f"Request URL: {resp.request.url}")
                print(f"Request Method: {resp.request.method}")
                print("Request Headers:")
                for key, value in resp.request.headers.items():
                    print(f"  {key}: {value}")
                if resp.request.body:
                    try:
                        body_json = json.loads(resp.request.body.decode('utf-8'))
                        print(f"Request Body:\n{json.dumps(body_json, indent=2)}")
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        print(f"Request Body: {resp.request.body}")
                print("-" * 20)
                print(f"Response Status: {resp.status_code} {resp.reason}")
                print("Response Headers:")
                for key, value in resp.headers.items():
                    print(f"  {key}: {value}")
                print("--- END CVE LOOKUP DEBUG ---\n")

            logging.info(f'POST to {url} | Status: {resp.status_code} | CVEs: {cves_p}')
            if resp.status_code == 200:
                response_data = resp.json().get('vulnerabilities', [])
                for vuln_object in response_data:
                    cve = vuln_object.get('cve_id')
                    if not cve: continue
                    cves_with_resp.append(cve)
                    
                    # Correctly parse the CVSS scores object
                    v3_base = ""
                    scores_dict = vuln_object.get("common_vulnerability_scores", {})
                    if scores_dict:
                        if "v3.1" in scores_dict:
                            v3_base = scores_dict["v3.1"].get("base_score", "")
                        elif "v3.0" in scores_dict:
                            v3_base = scores_dict["v3.0"].get("base_score", "")

                    merged_data = {
                        "CveId": cve,
                        "UrlSuffixId": vuln_object.get('id', ''),
                        "ExploitRating": null_to_dash(vuln_object.get("exploitation_state", "No Known")),
                        "RiskRating": null_to_dash(vuln_object.get("risk_rating", "-")),
                        #"Title": replace_chars(null_to_dash(vuln_object.get('description'))),
                        "Title": null_to_dash(vuln_object.get('description')),
                        "PublishedDate": trim_date_part(vuln_object.get('publish_date')),
                        "V3_BaseScore": v3_base,
                        "UserInteraction": "N/A", "AssociatedActors": [], "AssociatedMalware": [],
                        "ExploitationVector": [], "DateOfDisclosure": "N/A", "WasZeroDay": "N/A",
                        "V3_TemporalScore": "N/A", "V2_BaseScore": "N/A", "V2_TemporalScore": "N/A"
                    }

                    contexts = cve_context_map.get(cve, [{}])
                    for context in contexts:
                        output_arr.append({**merged_data, **context})
                
                unknown_cves = diff_list(cves_p, cves_with_resp)
                return (output_arr, [], unknown_cves)
            else:
                logging.info(f'resp.status_code: {resp.status_code} with input length: {len(cves_p)}')
                return ([], [], cves_p)
    except Exception as e:
        logging.exception(f'An exception occurred in post_vuln_lookup for cves: {cves_p}', exc_info=True)
        return ([], cves_p, [])


def null_to_dash(data):
        return data if data else "-"

def setup_logs(vulnfile):
    start_time = int(time.time())
    input_path = Path(vulnfile)
    log_dir = input_path.parent / "logs"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / f"{input_path.stem}_{start_time}.log"
    
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(levelname)s --> %(asctime)s: %(message)s', datefmt='%m/%d/%Y %H:%M:%S', filemode='w')
    logging.info(f'Start time of execution: {start_time}')

def check_for_commas(input_str):
        return f'"{input_str}"' if "," in str(input_str) else str(input_str)

def write_csv(output_filename_base, data_to_write):
    """Writes the final enriched data to a CSV file."""
    output_path = f"{output_filename_base}.csv"
    with open(output_path, 'w', encoding='utf-8', newline='') as csv_content:
        csv_content.write("CveId,Title,EntityName,IssueSeverity,IssueConfidence,ExploitRating,RiskRating,PublishedDate\n")
        for cve_data in data_to_write:
            line = ",".join([
                check_for_commas(cve_data.get("CveId", "")),
                check_for_commas(cve_data.get("Title", "")),
                check_for_commas(cve_data.get("EntityName", "")),
                check_for_commas(cve_data.get("IssueSeverity", "")),
                check_for_commas(cve_data.get("IssueConfidence", "")),
                check_for_commas(cve_data.get("ExploitRating", "")),
                check_for_commas(cve_data.get("RiskRating", "")),
                check_for_commas(cve_data.get("PublishedDate", "")),
            ])
            csv_content.write(line + "\n")
    logging.info(f"CSV output file {output_path} written!")

def embed_static_assets(html_content, output_file_path):
    """
    Finds linked CSS files in an HTML string, reads their content,
    and replaces the links with the embedded content.
    JavaScript files are left as links to the static folder.
    """
    output_dir = Path(output_file_path).parent

    # Embed CSS
    css_pattern = re.compile(r'<link.*?href=(["\'])([^"\']+?\.css)\1.*?>', re.IGNORECASE)
    
    # Create a new list of matches to iterate over, as we'll be modifying the string
    css_matches = list(css_pattern.finditer(html_content))
    
    for match in css_matches:
        original_tag, css_relative_path = match.group(0), match.group(2)
        try:
            # Resolve path relative to the output directory
            css_full_path = (output_dir / css_relative_path).resolve(strict=True)
            logger.info(f"Embedding CSS from: {css_full_path}")
            with open(css_full_path, 'r', encoding='utf-8') as f:
                css_content = f.read()
            replacement_tag = f'<style type="text/css">\n{css_content}\n</style>'
            html_content = html_content.replace(original_tag, replacement_tag)
        except Exception as e:
            logger.error(f"SKIPPING: Error embedding CSS file {css_relative_path}: {e}")
            
    # NOTE: We are no longer embedding JavaScript to avoid parsing errors.
    # The final HTML will link to the JS files in the 'static' directory.
    
    return html_content            

# MODIFIED: Refactored to remove global variables and handle data processing cleanly.
def main_post(input_filename, project_id="N/A", project_name="N/A", generate_csv=True, debug=False, noverify=False, advantage_mode=False):
    """
    Main function for the CVE lookup. Uses Mandiant Intelligence API.
    """
    global template, exit_event
    
    vulnfilename = Path(input_filename).stem
    input_path = Path(input_filename)
    output_dir = input_path.parent.parent
    output_path_base = output_dir / input_path.stem
    
    # Define local lists to hold results for this specific run
    output_data = []
    failed_cves = []
    unknown_cves = []
    
    exit_event = threading.Event()

    print(f'\nNOTE: {__note__}\n')
    
    token = get_mati_token(debug)
    headers = {
        "Authorization": f"Bearer {token}", "Content-Type": "application/json",
        "Accept": "application/json", "X-App-Name": "gsa-labs"
    }

    if advantage_mode:
        logo_filename = "ma_logo.png"
        base_vuln_url = "https://advantage.mandiant.com/vulnerabilities/"
    else:
        logo_filename = "gti_logo.png"
        base_vuln_url = "https://www.virustotal.com/gui/collection/"
    logo_path = f"static/images/{logo_filename}"

    load_template(debug=debug)
    # Setup signal handler with necessary context
    handler = lambda signum, frame: signal_handler(signum, frame, output_path_base, generate_csv, output_data, template, logo_filename, base_vuln_url, debug)
    signal.signal(signal.SIGINT, handler)
    setup_logs(input_filename)

    try:
        script_dir = Path(__file__).parent
        source_static_dir = script_dir / "templates" / "static"
        dest_static_dir = output_dir / "static"

        if source_static_dir.is_dir():
            if dest_static_dir.exists(): shutil.rmtree(dest_static_dir)
            print(f"Copying static assets to '{dest_static_dir}'...")
            shutil.copytree(source_static_dir, dest_static_dir)
        else:
            print(f"Warning: Source asset folder not found at '{source_static_dir}'. Report may not be styled correctly.")

        collection_root_dir = input_path.parent.parent
        cve_context_map = build_cve_context_from_json_files(collection_root_dir, debug)
     
        cves = regex_file(input_filename)
        logging.info(f'Executing file: {input_filename} which has a total of {len(cves)} unique CVEs.')
        input_length = len(cves)

        if not cves:
            print(f"No CVEs found in '{input_filename}'. Skipping report generation.")
            return

        # Start the progress bar thread, passing the lists it needs to monitor
        progress_thread = threading.Thread(target=show_progress, args=(output_data, failed_cves, len(unknown_cves), input_length))
        progress_thread.start()

        with ThreadPoolExecutor(max_workers=50) as executor:
            # Each future will return a tuple: (success_list, failed_list, unknown_list)
            futures = [executor.submit(post_vuln_lookup, chunk, headers, cve_context_map, noverify, debug) for chunk in divide_chunks(cves, 100)]
            for future in futures:
                success_data, failed_data, unknown_data = future.result()
                if success_data: output_data.extend(success_data)
                if failed_data: failed_cves.extend(failed_data)
                if unknown_data: unknown_cves.extend(unknown_data)
        
        exit_event.set() # Signal the progress thread to stop
        progress_thread.join()
        
        logging.info(f'POST execution details:: successful: {len(output_data)}, failed: {len(failed_cves)}, unknown: {len(unknown_cves)}')
       
        # 1. Get the current date
        report_date = strftime("%B %d, %Y") # e.g., "November 05, 2025"

        # 2. Get the stored metadata
        metadata = global_scan_filters.get(input_filename, {})

        # Get the clean data, with fallbacks just in case
        report_collection_name = metadata.get("collection_name", vulnfilename) 
        report_data_type = metadata.get("data_type", "data").capitalize() # e.g., "Issues"
        last_scan_info = metadata.get("scan_info", "N/A")

        # Create the dynamic description using the clean collection name
        report_description = f"This report summarizes findings from the {report_collection_name} assessment, detailing vulnerabilities and associated risks."

        output_html_path = f"{output_path_base}_cve_report.html"
        
        rendered_html = template.render(
            cve_data=output_data, 
            vulnfilename=vulnfilename, 
            logo_file_path=logo_path,
            base_vuln_url=base_vuln_url,
            report_date=report_date,
            report_description=report_description,
            project_name=project_name, 
            project_id=project_id,
            last_scan_info=last_scan_info,
            report_collection_name=report_collection_name,
            report_data_type=report_data_type
        )
        
        final_html_content = embed_static_assets(rendered_html, output_html_path)

        with open(output_html_path, 'w', encoding='utf-8') as final_file:
            final_file.write(final_html_content)

        if generate_csv:
            write_csv(f"{output_path_base}_cve_report", output_data)

        logging.info(f"Output file {output_html_path} written!")
        print(f"\nReport generation for '{input_filename}' completed. See {output_html_path}")
    except Exception as e:
        logging.exception(f"Execution failed for file '{input_filename}' with reason:\n{e}", exc_info=True)
        print(f"Execution failed for file '{input_filename}' with reason:\n{e}")

# ==============================================================================
# ===== ISSUE DETAIL FETCHING AND WORKFLOW ORCHESTRATION =======================
# ==============================================================================
def redact_api_key_from_headers(headers):
    """Creates a copy of a headers dictionary with the API key redacted."""
    headers_copy = dict(headers)
    for key in list(headers_copy.keys()):
        if key.lower() in ['x-apikey', 'intrigue_access_key', 'intrigue_secret_key']:
            headers_copy[key] = '***REDACTED***'
    return headers_copy

async def fetch_issue_details(session, issue_id, semaphore, debug):
    """
    Fetches details for a single issue ID, with retry logic.
    """
    url = f"{ASM_URL_BASE}issues/{issue_id}"
    max_retries, backoff_factor = 5, 2

    async with semaphore:
        for attempt in range(max_retries):
            try:
                async with session.get(url) as response:
                    if debug:
                        redacted_headers = redact_api_key_from_headers(response.request_info.headers)
                        logger.debug(f"URL: {response.url} | Attempt: {attempt + 1}/{max_retries} | Status: {response.status}")
                    response.raise_for_status()
                    data = await response.json()
                    if debug: logger.debug(f"Received JSON for issue {issue_id}: {json.dumps(data, indent=2)}")
                    return data.get('result', data.get('data', data))
            except (aiohttp.ClientResponseError, aiohttp.ClientError, asyncio.TimeoutError) as e:
                if isinstance(e, aiohttp.ClientResponseError) and e.status < 500:
                    logger.error(f"Client error {e.status} for issue {issue_id}. Not retriable.")
                    return None
                if attempt < max_retries - 1:
                    sleep_time = backoff_factor * (2 ** attempt)
                    if debug: logger.warning(f"Retriable error for {issue_id}. Retrying in {sleep_time}s...")
                    await asyncio.sleep(sleep_time)
                else:
                    logger.error(f"Giving up on issue {issue_id} after {max_retries} attempts. Final error: {e}.")
            except Exception as e:
                logger.error(f"An unexpected error occurred for issue {issue_id}: {e}", exc_info=True)
                return None
    return None

async def process_and_fetch_issue_details(issues_csv_filename, project_id, debug, concurrency_limit, base_headers, noverify=False):
    """
    Reads an issues CSV, fetches detailed information for each issue, and saves results.
    """
    print(f"\n--- Starting Step 2: Fetching Full Details for Issues ---")
    print(f"Reading issue IDs from '{issues_csv_filename}'...")

    try:
        df = pd.read_csv(issues_csv_filename)
        if 'id' not in df.columns:
            print(f"Error: 'id' column not found in '{issues_csv_filename}'.")
            return
        issue_ids = df['id'].dropna().unique().tolist()
        if not issue_ids:
            print("No issue IDs found in the file to process.")
            return
    except Exception as e:
        print(f"Error reading or processing CSV file '{issues_csv_filename}': {e}")
        return

    print(f"Found {len(issue_ids)} unique issue IDs to query for full details.")
    
    # This block is removed as headers are now passed in:
    # advantage_mode = "-adv" in sys.argv
    # try:
    #     if advantage_mode:
    #         base_headers = load_adv_asm_credentials(debug)
    #     else:
    #         googleti_api_key = load_credentials()
    #         base_headers = {"X-Apikey": f"{googleti_api_key}"}
    # except SystemExit as e:
    #     print(f"Could not load credentials to fetch issue details: {e}")
    #     return

    base_headers["PROJECT-ID"] = str(project_id)
    
    if debug:
        print(f"[DEBUG] Initializing issue detail session with headers: {redact_api_key_from_headers(base_headers)}")
    
    semaphore = asyncio.Semaphore(concurrency_limit)
    connector = aiohttp.TCPConnector(ssl=False if noverify else None)
    async with aiohttp.ClientSession(headers=base_headers, connector=connector) as session:
        tasks = [fetch_issue_details(session, issue_id, semaphore, debug) for issue_id in issue_ids]
        results = await tqdm.gather(*tasks, desc="Fetching Issue Details", unit="issue")

    successful_details = [res for res in results if res is not None]
    if not successful_details:
        print("\nCould not fetch details for any issues.")
        return

    print(f"\nSuccessfully fetched details for {len(successful_details)} out of {len(issue_ids)} issues.")

    collection_root_dir = Path(issues_csv_filename).parent.parent
    output_dir = collection_root_dir / "issuesDetail"
    output_dir.mkdir(exist_ok=True)

    print(f"\nSaving {len(successful_details)} issue detail files to '{output_dir}'...")
    saved_count = 0
    for issue in successful_details:
        try:
            issue_id = issue.get('uid')
            if issue_id:
                pretty_name = re.sub(r'[^a-zA-Z0-9_-]', '_', issue.get('pretty_name', 'UnknownIssue'))
                entity_name = re.sub(r'[^a-zA-Z0-Z0-9._-]', '_', issue.get('entity_name', 'UnknownEntity'))
                descriptive_filename = f"{pretty_name}_{entity_name}_{issue_id[:8]}.json"
                with open(output_dir / descriptive_filename, 'w', encoding='utf-8') as f:
                    json.dump(issue, f, indent=4)
                saved_count += 1
        except Exception as e:
            logger.error(f"Failed to save detail file for issue ID {issue.get('uid', 'N/A')}: {e}")

    print(f"✅ Success: Saved {saved_count} detailed issue JSON files in '{output_dir}'.")

def prompt_for_cve_report():
    """Prompts the user to decide if they want to run the CVE vulnerability report."""
    return get_yes_no("\nWould you like to generate a CVE vulnerability report from the exported files?")

async def run_full_workflow():
    """Orchestrates the full workflow."""
    noverify = "-noverify" in sys.argv
    if noverify:
        print("\n" + "="*60 + "\n" + "WARNING: SSL VERIFICATION DISABLED".center(60) + "\n" + "="*60)

    concurrency_limit = 100
    if "-concurrency" in sys.argv:
        try:
            concurrency_limit = int(sys.argv[sys.argv.index("-concurrency") + 1])
            print(f"Concurrency limit set to {concurrency_limit} requests.")
        except (ValueError, IndexError):
            print("Warning: Invalid value for -concurrency. Using default of 100.")

    print("--- Starting Step 1: ASM Data Export ---")
    generated_files, project_id, project_name, debug, project_dir_name, base_headers = await main(noverify=noverify)

    if not generated_files or not project_id:
        print("\nNo files were generated or project ID was not found. Exiting workflow.")
        return

    print("\n--- Step 1 Complete: ASM Data Export Finished ---")
    
    issues_files = [f for f in generated_files if '_issues_' in f]
    if issues_files:
        for issues_file in issues_files:
            await process_and_fetch_issue_details(issues_file, project_id, debug, concurrency_limit, base_headers, noverify=noverify)
    else:
        print("\nNo issues files found, skipping the issue detail fetching step.")

    if prompt_for_cve_report():
        print("\n--- Starting Step 3: Generating CVE Reports from Exported Files ---")
        advantage_mode = "-adv" in sys.argv
        for filename in generated_files:
            if '_issues_' in filename or '_technologies_' in filename:
                print(f"\n{'='*58}\nProcessing file for CVE report: '{filename}'...\n{'='*58}")
                main_post(input_filename=filename, project_id=project_id, project_name=project_name, debug=debug, noverify=noverify, advantage_mode=advantage_mode)
            else:
                print(f"\nSkipping CVE report for '{filename}' as it's not an issues or technologies file.")
    else:
        print("\nSkipping CVE vulnerability report generation as requested.")

    if generated_files and project_dir_name:
        await prompt_and_upload_to_gcp(project_dir_name)
    else:
        print("\nNo files were generated, skipping final upload step.")
    
    print("\n--- Workflow Finished ---")

async def prompt_for_gcp_bucket():
    """Prompts user to select if they want to upload to GCP."""
    print("\n" + "="*50 + "\n" + "Final Step: Upload Report to GCP".center(50) + "\n" + "="*50)
    
    if not GCP_ENABLED:
        print("\nNote: GCP Cloud Storage library not found (pip install google-cloud-storage). Cannot upload.")
        return None

    if get_yes_no("\nWould you like to upload the entire report folder to GCP?"):
        bucket_name = select_gcp_bucket_interactive()
        if not bucket_name:
             print("No bucket selected. Skipping upload.")
             return None
        return bucket_name

    return None

async def prompt_and_upload_to_gcp(project_dir_name):
    """Orchestrates the final upload."""
    bucket_name = await prompt_for_gcp_bucket()
    if not bucket_name:
        return

    project_path = Path(project_dir_name)
    if not project_path.is_dir():
        print(f"Error: Project directory '{project_dir_name}' not found.")
        return

    try:
        print("Initializing Google Cloud Storage client...")
        client = storage.Client()
        bucket = client.bucket(bucket_name)
    except Exception as e:
        print(f"❌ Error initializing GCP client: {e}\nPlease check authentication and bucket name.")
        return

    print(f"\nArchiving project folder '{project_dir_name}' for upload...")
    zip_output_base = Path.cwd() / f"{project_dir_name}_report"
    zip_file_name = f"{zip_output_base}.zip"
    
    loop = asyncio.get_running_loop()
    
    try:
        await loop.run_in_executor(None, shutil.make_archive, str(zip_output_base), 'zip', Path.cwd(), project_dir_name)
        print(f"Archive created: {zip_file_name}")

        with AsyncThreadPoolExecutor() as pool:
            upload_tasks = []
            upload_tasks.append(async_upload_file(pool, bucket, zip_file_name, Path(zip_file_name).name))
            
            report_files = list(project_path.rglob("*_cve_report.html"))
            if report_files:
                print(f"Found {len(report_files)} HTML report(s) to upload separately...")
                for report_path in report_files:
                    report_blob_name = str(report_path).replace(os.path.sep, '/')
                    upload_tasks.append(async_upload_file(pool, bucket, str(report_path), report_blob_name))
            
            print(f"\nStarting {len(upload_tasks)} concurrent uploads...")
            results = await tqdm.gather(*upload_tasks, desc="Uploading", unit="file")
        
        print("\n--- GCP Upload Summary ---")
        for blob_name, success, error_msg in results:
            if success:
                print(f"  - ✅ Success: gs://{bucket_name}/{blob_name}")
            else:
                print(f"  - ❌ Error uploading {blob_name}: {error_msg}")
    except Exception as e:
        print(f"An error occurred during zipping or uploading: {e}")
        traceback.print_exc()
    finally:
        Path(zip_file_name).unlink(missing_ok=True)
        print(f"Cleaned up local zip file: {Path(zip_file_name).name}")

    if get_yes_no(f"Uploads complete. Delete the local project folder '{project_dir_name}'?"):
        try:
            shutil.rmtree(project_path)
            print(f"✅ Successfully deleted local folder: {project_dir_name}")
        except OSError as e:
            print(f"❌ Error: Could not delete folder {project_dir_name}: {e}")

if __name__ == "__main__":
    if "-h" in sys.argv or "--help" in sys.argv:
        print_usage()
        sys.exit(0)
    
    while True:
        try:
            asyncio.run(run_full_workflow())
        except KeyboardInterrupt:
            print("\nProcess interrupted by user. Exiting.")
            sys.exit(0)
        except Exception as e:
            print(f"\n{'='*66}\nAN UNEXPECTED ERROR OCCURRED (SEE STACK TRACE BELOW)\n{'='*66}")
            traceback.print_exc()
        
        if not get_yes_no("\nWould you like to process another project?"):
            print("\nExiting script. Goodbye!")
            break
        print("\nRestarting workflow...")
