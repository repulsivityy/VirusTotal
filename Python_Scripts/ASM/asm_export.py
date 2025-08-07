#####################################
# This script exports entities, issues, or technologies from a selected Google Threat Intelligence ASM project.
# and outputs the results to a CSV file in the local directory or a GCP Cloud Storage bucket.

# requirements:
# - Google Threat Intelligence API Key (set as environment variable GTI_APIKEY)
# export GTI_APIKEY="your_api_key_here"

# author: dominicchua@ (adapted from https://github.com/chrismralph/gti-asm-export)
# version: 1.0
# USE AT YOUR OWN RISK
#####################################


import platform
import warnings

import os
import sys
import json
import pandas as pd
from pathlib import Path
import io
import logging
import argparse

# --- Asynchronous Operations ---
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

# --- SCRIPT DEPENDENCIES ---
# This script requires the following third-party libraries:
# pip install pandas aiohttp google-cloud-storage

# --- GCP Integration (Conditional Import) ---
try:
    from google.cloud import storage
    from google.api_core.exceptions import GoogleAPICallError
    GCP_ENABLED = True
except ImportError:
    GCP_ENABLED = False


# --- Constants ---
ASM_URL_BASE = "https://www.virustotal.com/api/v3/asm/"
PROJECTS_ENDPOINT = "projects"
COLLECTIONS_ENDPOINT = "user_collections/"
ENTITIES_ENDPOINT = "search/entities"
ISSUES_ENDPOINT = "search/issues/"
TECHNOLOGIES_ENDPOINT = "search/technologies/"

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format=f"%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


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

def parse_arguments():
    """Parses command-line arguments using argparse."""
    parser = argparse.ArgumentParser(
        description="This script will export entities, issues, or technologies from a selected Google Threat Intelligence ASM project.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Workflow:
  1. Select a Project.
  2. Choose to export from a single collection or ALL collections.
  3. Select the data type to export.
  4. Choose to save results to a Local Directory or a GCP Storage Bucket.
  5. Data is fetched and saved to the chosen destination.
"""
    )
    parser.add_argument(
        '-key',
        dest='api_key',
        help="Bypass environment variable and provide the API key directly."
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=False,
        help="Enable debug output. (Default: Disabled)"
    )
    parser.add_argument(
        '-nobanner',
        action='store_true',
        help="Suppress the disclaimer banner."
    )
    return parser.parse_args()


def load_credentials(args):
    """Loads API credentials from command-line argument or environment variable."""
    if args.api_key:
        logger.info("Using API key provided via -key argument.")
        return args.api_key
    
    googleti_api_key = os.getenv("GTI_APIKEY")
    if not googleti_api_key:
        raise SystemExit("Error: 'GTI_APIKEY' environment variable not set. Please set it or use the '-key' option.")

    logger.info("Using API key from GTI_APIKEY environment variable.")
    return googleti_api_key


def select_export_type():
    """Prompts the user to select the type of data to export."""
    print("\nWhat data would you like to export from the selected collection(s)?")
    print("\t 1. Entities")
    print("\t 2. Issues")
    print("\t 3. Technologies")
    print("\t 4. All (Entities, Issues, and Technologies) - Asynchronously")

    while True:
        try:
            choice = int(input("\nEnter the number of your choice: "))
            if choice in [1, 2, 3, 4]:
                return {1: "entities", 2: "issues", 3: "technologies", 4: "all"}[choice]
            else:
                print("Invalid choice. Please enter 1, 2, 3, or 4.")
        except ValueError:
            print("Invalid input. Please enter a number.")


async def select_output_destination_async():
    """Prompts user to select the output destination."""
    print("\nWhere would you like to store the results?")
    print("\t 1. Local Directory (in the same folder as the script)")
    print("\t 2. GCP Cloud Storage Bucket")

    if not GCP_ENABLED:
        print("\nNote: GCP Cloud Storage library not found. To use the GCP feature,")
        print("please install it by running: pip install google-cloud-storage")
        print("Defaulting to Local Directory.")
        return "local", None

    while True:
        try:
            choice = int(input("\nEnter the number of your choice: "))
            if choice == 1:
                return "local", None
            elif choice == 2:
                bucket_name = input("Enter the name of your GCP Cloud Storage bucket: ").strip()
                if not bucket_name:
                    print("Bucket name cannot be empty. Please try again.")
                    continue
                print("\nIMPORTANT: Ensure you have authenticated with GCP for this script to work.")
                print("You can do this by running: 'gcloud auth application-default login'")
                return "gcp", bucket_name
            else:
                print("Invalid choice. Please enter 1 or 2.")
        except ValueError:
            print("Invalid input. Please enter a number.")


async def get_project_id(session, debug):
    """Fetches projects and prompts for selection asynchronously."""
    print("\nFetching projects...")
    try:
        async with session.get(ASM_URL_BASE + PROJECTS_ENDPOINT) as projects_response:
            projects_response.raise_for_status()
            response_json = await projects_response.json()

            if debug:
                logger.debug("\n--- Raw JSON Response for Projects ---\n%s\n-------------------------------------------\n", json.dumps(response_json, indent=2))

    except aiohttp.ClientError as e:
        logger.error(f"Error retrieving projects: {e}")
        return None, None
    
    projects_data = response_json.get('result', [])
    if not projects_data:
        logger.warning("No projects found for this API key.")
        return None, None

    print("\nAvailable Projects To Select From:")
    for index, project in enumerate(projects_data):
        print(f"\t {index + 1}. {project.get('name', 'Unnamed Project')}")
    while True:
        try:
            choice = int(input("\nEnter the number of the project: ")) - 1
            if 0 <= choice < len(projects_data):
                selected_project = projects_data[choice]
                return selected_project['id'], selected_project['organization_name']
            else:
                print("Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")


async def select_collections_to_process(session, debug):
    """Fetches collections, filters out deleted ones for selection, and prompts the user."""
    print(f"\nFetching collections for the selected project...")
    try:
        async with session.get(ASM_URL_BASE + COLLECTIONS_ENDPOINT) as collections_response:
            collections_response.raise_for_status()
            response_json = await collections_response.json()

            if debug:
                logger.debug("\n--- Raw JSON Response for Collections ---\n%s\n-------------------------------------------\n", json.dumps(response_json, indent=2))

    except aiohttp.ClientError as e:
        logger.error(f"Error retrieving collections: {e}")
        return None

    collections = response_json.get('result', [])
    if not collections:
        logger.warning("No collections found in this project.")
        return None

    active_collections = [c for c in collections if not c.get('deleted', False)]
    deleted_collections = [c for c in collections if c.get('deleted', False)]

    print("\nAvailable Collections To Select From:")
    if active_collections:
        print(f"\t 0. All Collections")
        for index, collection in enumerate(active_collections):
            name = collection.get('printable_name', collection.get('name', 'Unnamed Collection'))
            print(f"\t {index + 1}. {name}")
    else:
        print("\t No active collections available for this project.")

    if deleted_collections:
        print("\nDeleted Collections:")
        for collection in deleted_collections:
            name = collection.get('printable_name', collection.get('name', 'Unnamed Collection'))
            print(f"\t [DELETED] {name}")

    while True:
        if not active_collections:
            print("\nNo active collections to process. Exiting selection.")
            return None
        
        try:
            choice = int(input("\nEnter the number of the collection (or 0 for All): "))
            if choice == 0:
                return active_collections
            elif 1 <= choice <= len(active_collections):
                return [active_collections[choice - 1]]
            else:
                print("Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")


async def get_paginated_data(session, base_query_url, debug, blob_name, data_type_name, printable_collection_name):
    """Fetches paginated data and returns it in an in-memory CSV buffer."""
    all_hits = []
    logger.info(f"Starting fetch for '{data_type_name}' from collection '{printable_collection_name}'...")
    next_page_url = base_query_url

    while next_page_url:
        if debug:
            logger.debug(f"({printable_collection_name}): Requesting URL: {next_page_url}")

        try:
            async with session.get(next_page_url) as response:
                response.raise_for_status()
                data = await response.json()
        except (aiohttp.ClientError, json.JSONDecodeError) as e:
            logger.error(f"Error fetching data for {data_type_name} from '{printable_collection_name}': {e}")
            break

        hits_on_page = data.get('result', {}).get('hits', [])
        if not hits_on_page:
            break

        all_hits.extend(hits_on_page)

        next_page_token = data.get('result', {}).get('next_page_token')
        if next_page_token:
            next_page_url = f"{base_query_url}&page_token={next_page_token}"
        else:
            break
            
    csv_buffer = None
    total_count = len(all_hits)
    if all_hits:
        logger.info(f"Fetched {total_count} '{data_type_name}' from '{printable_collection_name}'. Preparing CSV data.")
        try:
            df = pd.DataFrame(all_hits)
            csv_buffer = io.StringIO()
            df.to_csv(csv_buffer, index=False)
        except Exception as e:
            logger.error(f"Error creating CSV buffer for {blob_name}: {e}")
            return total_count, data_type_name, blob_name, printable_collection_name, None
    else:
        logger.info(f"No results found for '{data_type_name}' in '{printable_collection_name}'.")

    return total_count, data_type_name, blob_name, printable_collection_name, csv_buffer


def upload_file_to_gcs(bucket_name, source_file_path, destination_blob_name):
    """Uploads a file to a GCS bucket (blocking)."""
    try:
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)

        logger.info(f"Uploading '{source_file_path}' to bucket '{bucket_name}' as '{destination_blob_name}'...")
        blob.upload_from_filename(source_file_path)
        logger.info("✅ Upload successful for '%s'.", destination_blob_name)
        return True, None
    except Exception as e:
        logger.exception("❌ Upload failed for '%s'.", destination_blob_name)
        return False, str(e)

async def async_upload_file(bucket_name, source_file_path, destination_blob_name):
    """Async wrapper for upload_file_to_gcs using ThreadPoolExecutor."""
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor() as pool:
        success, error_msg = await loop.run_in_executor(
            pool, 
            upload_file_to_gcs, 
            bucket_name, 
            source_file_path, 
            destination_blob_name
        )
        return destination_blob_name, success, error_msg


async def _update_timer(start_time):
    """A background task that prints the elapsed time every 5 seconds."""
    while True:
        elapsed_seconds = asyncio.get_event_loop().time() - start_time
        print(f"\r[*] Processing... {elapsed_seconds:.0f}s", end="", flush=True)
        await asyncio.sleep(5)

async def main():
    """Main asynchronous workflow."""
    args = parse_arguments()

    if not args.nobanner:
        display_disclaimer()
    
    try:
        googleti_api_key = load_credentials(args)
    except SystemExit as e:
        logger.error(e)
        sys.exit(1)

    debug = args.debug
    base_headers = {"X-Apikey": f"{googleti_api_key}"}

    start_time = asyncio.get_event_loop().time()
    timer_task = None
    try:
        if not debug:
            timer_task = asyncio.create_task(_update_timer(start_time))

        async with aiohttp.ClientSession(headers=base_headers) as session:
            project_id, organization_name = await get_project_id(session, debug)
            if not project_id:
                return
            
            logger.info(f"Project '{organization_name}' selected.")
            session.headers.update({'PROJECT-ID': str(project_id)})

            collections_to_process = await select_collections_to_process(session, debug)
            if not collections_to_process:
                return
            
            export_type = select_export_type()
            output_destination, gcp_bucket_name = await select_output_destination_async()

            if timer_task: print() # Move to the next line after user inputs
            print("-" * 50)
            
            fetch_tasks = []
            endpoints = {"entities": ENTITIES_ENDPOINT, "issues": ISSUES_ENDPOINT, "technologies": TECHNOLOGIES_ENDPOINT}
            data_types_to_fetch = endpoints.keys() if export_type == 'all' else [export_type]

            for collection in collections_to_process:
                printable_name = collection.get('printable_name', collection['name'])
                safe_printable_name = "".join(c for c in printable_name if c.isalnum() or c in (' ', '_')).rstrip().replace(' ', '_')
                for data_type in data_types_to_fetch:
                    blob_name = f"{safe_printable_name}_{data_type}_{project_id}.csv"
                    base_url = f"{ASM_URL_BASE}{endpoints[data_type]}/collection:{collection['name']}?page_size=1000"
                    task = get_paginated_data(session, base_url, debug, blob_name, data_type, printable_name)
                    fetch_tasks.append(task)
            
            fetch_results = []
            if fetch_tasks:
                logger.info(f"Starting {len(fetch_tasks)} data fetch task(s)...")
                fetch_results = await asyncio.gather(*fetch_tasks)

            output_summary = {}

            if output_destination == 'local':
                logger.info("Writing results to local files...")
                for _, data_type, filename, coll_name, csv_buffer in fetch_results:
                    if coll_name not in output_summary: output_summary[coll_name] = []
                    if csv_buffer:
                        try:
                            with open(filename, 'w', encoding='utf-8') as f:
                                csv_buffer.seek(0)
                                f.write(csv_buffer.getvalue())
                            output_summary[coll_name].append(f"  - ✅ Success: Saved {data_type} to '{filename}'")
                        except IOError as e:
                            output_summary[coll_name].append(f"  - ❌ Error: Failed to write {data_type} to '{filename}': {e}")
                    else:
                        output_summary[coll_name].append(f"  - ℹ️ No data found for {data_type}.")

            elif output_destination == 'gcp' and gcp_bucket_name:
                logger.info(f"Saving temporary files and queueing uploads to GCP bucket: {gcp_bucket_name}...")
                upload_tasks = []
                temp_files = [] 
                results_map = {}

                for _, data_type, blob_name, coll_name, csv_buffer in fetch_results:
                    if coll_name not in output_summary: output_summary[coll_name] = []
                    if csv_buffer:
                        temp_file_path = Path(blob_name)
                        temp_files.append(temp_file_path)
                        try:
                            with open(temp_file_path, 'w', encoding='utf-8') as f:
                                csv_buffer.seek(0)
                                f.write(csv_buffer.getvalue())
                            results_map[blob_name] = (data_type, coll_name)
                            task = async_upload_file(gcp_bucket_name, str(temp_file_path), blob_name)
                            upload_tasks.append(task)
                        except IOError as e:
                            output_summary[coll_name].append(f"  - ❌ Error: Failed to write temporary file for {data_type}: {e}")
                    else:
                        output_summary[coll_name].append(f"  - ℹ️ No data found for {data_type}.")
                
                if upload_tasks:
                    logger.info(f"Starting {len(upload_tasks)} concurrent uploads...")
                    upload_results = await asyncio.gather(*upload_tasks)
                    for blob_name, success, error_msg in upload_results:
                        data_type, coll_name = results_map[blob_name]
                        if success:
                            output_summary[coll_name].append(f"  - ✅ Success: Uploaded {data_type} to gs://{gcp_bucket_name}/{blob_name}")
                        else:
                            output_summary[coll_name].append(f"  - ❌ Error: Failed to upload {data_type} to '{blob_name}': {error_msg}")

                logger.info("Cleaning up temporary local files...")
                for f in temp_files:
                    try:
                        f.unlink()
                    except OSError as e:
                        logger.warning(f"Could not delete temporary file {f}: {e}")

            # Final Summary Printout
            print("\n" + "="*50)
            print("                  Export Summary")
            print("="*50)
            for collection_name, messages in sorted(output_summary.items()):
                print(f"\nCollection: '{collection_name}'")
                for msg in messages:
                    print(msg)
            print("\n" + "="*50)

    finally:
        if timer_task:
            timer_task.cancel()
            print() # Move to the next line
        
        end_time = asyncio.get_event_loop().time()
        total_duration = end_time - start_time
        logger.info(f"Total time taken: {total_duration:.2f} seconds.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An unexpected critical error occurred: {e}", exc_info=True)
        sys.exit(1)