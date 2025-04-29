import functions_framework
import base64
import json
import os
import time
import requests
import sys # Import sys for detailed error info (optional)
import traceback # Import traceback for detailed error info (optional)


from google.cloud import storage
from google.cloud import exceptions

# --- Configuration (Read from Environment Variables at deployment) ---
PROJECT_ID = os.environ.get("GCP_PROJECT")
#####Possible security risk#####
# Reading API key directly from environment variable is insecure for production.
GTI_APIKEY = os.environ.get("GTI_APIKEY")
# --- End Security Risk ---
ALLOW_BUCKET_NAME = os.environ.get("ALLOW_BUCKET")
QUARANTINE_BUCKET_NAME = os.environ.get("QUARANTINE_BUCKET")

# --- Private Scanning Payload Options ---
GTI_DISABLE_SANDBOX = os.environ.get("GTI_DISABLE_SANDBOX", "true")
GTI_INTERCEPT_TLS = os.environ.get("GTI_INTERCEPT_TLS", "true")
GTI_RETENTION_DAYS = os.environ.get("GTI_RETENTION_DAYS", "1")
GTI_STORAGE_REGION = os.environ.get("GTI_STORAGE_REGION", "US")
GTI_LOCALE = os.environ.get("GTI_LOCALE", "EN_US")
GTI_ENABLE_INTERNET = os.environ.get("GTI_ENABLE_INTERNET", "true")
# --- End Payload Options ---

# --- Other Config ---
GTI_TOOL_NAME = os.environ.get("GTI_TOOL_NAME", "gti_scanner_cf") # Updated tool name
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "15"))
MAX_POLL_TIME_SECONDS = int(os.environ.get("MAX_POLL_TIME_SECONDS", "480"))
# --- End Configuration ---

# Initialize clients outside function handler
try:
    storage_client = storage.Client()
except Exception as e:
    print(f"CRITICAL: Failed to initialize Storage client: {e}")
    storage_client = None # Indicate failure

# --- API Endpoints for Private Scanning ---
GTI_API_URL_PRIVATE_FILES_UPLOAD = "https://www.virustotal.com/api/v3/private/files"
GTI_API_URL_PRIVATE_ANALYSES = "https://www.virustotal.com/api/v3/private/analyses/{}"
GTI_API_URL_PRIVATE_FILES_INFO = "https://www.virustotal.com/api/v3/private/files/{}"


def move_blob(source_bucket_name, blob_name, destination_bucket_name):
    """Copies a blob, verifies, and deletes the source upon success."""
    if not storage_client:
        print("ERROR:[move_blob] Storage client not initialized.")
        return False

    try:
        source_bucket = storage_client.bucket(source_bucket_name)
        destination_bucket = storage_client.bucket(destination_bucket_name)
        source_blob = source_bucket.blob(blob_name)

        # Check source existence just before operating
        print(f"  Checking source blob gs://{source_bucket_name}/{blob_name}...")
        source_blob.reload() # Can raise exceptions.NotFound
        print(f"  Source blob found. Attempting copy to gs://{destination_bucket_name}/{blob_name}...")

        # === Step 1: Copy ===
        blob_copy = source_bucket.copy_blob(
            source_blob, destination_bucket, blob_name
        )
        print(f"  Copy operation initiated for {blob_name}.")

        # === Step 2: Verify Copy ===
        destination_blob = destination_bucket.blob(blob_name)
        try:
            destination_blob.reload() # Can raise exceptions.NotFound
            print(f"  Verification successful: Blob exists in {destination_bucket_name}.")
        except exceptions.NotFound: # <--- CORRECTED
            print(f"  ERROR: Verification failed! Copied blob not found in {destination_bucket_name}.")
            # Do NOT delete source if copy verification failed
            return False

        # === Step 3: Delete Source (only if copy+verify succeeded) ===
        try:
            print(f"  Deleting source blob gs://{source_bucket_name}/{blob_name}...")
            source_blob.delete() # <--- THE DELETION HAPPENS HERE
            print(f"  Source blob deleted.")
            print(f"Successfully moved {blob_name} from {source_bucket_name} to {destination_bucket_name}")
            return True # Indicate successful move (copy + delete)

        except exceptions.NotFound: # <--- CORRECTED
             print(f"  WARNING: Source blob gs://{source_bucket_name}/{blob_name} was not found during delete phase (maybe deleted concurrently?).")
             # If destination exists, consider the move successful overall.
             return True
        except Exception as e_del:
             print(f"  ERROR: Failed to delete source blob {blob_name} after copy: {e_del}")
             # File is copied but source remains. This might require manual cleanup.
             # Return False to indicate the full "move" operation wasn't clean.
             return False

    except exceptions.NotFound: # <--- CORRECTED
         print(f"ERROR:[move_blob] Source blob gs://{source_bucket_name}/{blob_name} not found at the start.")
         # Check if it's already in destination (idempotency check)
         try:
             dest_blob_check = storage_client.bucket(destination_bucket_name).blob(blob_name)
             dest_blob_check.reload() # Can raise exceptions.NotFound
             print(f"  Note: Blob {blob_name} already exists in destination {destination_bucket_name}. Considering 'move' successful.")
             return True
         except exceptions.NotFound: # <--- CORRECTED
              print(f"  Error: Blob {blob_name} not found in source or destination during initial check.")
              return False
    except Exception as e:
        print(f"ERROR:[move_blob] Unexpected error during move operation for {blob_name}: {e}")
        traceback.print_exc() # Uncomment for detailed debugging
        return False # Indicate move failed

@functions_framework.cloud_event
def scan_file_gti(cloud_event):
    """
    Cloud Function triggered by a Cloud Storage event (Eventarc).
    Uploads file for GTI Private Scanning, polls analysis, gets file report,
    and moves file based on the final verdict.
    """
    start_processing_time = time.time()
    event_data = cloud_event.data
    source_bucket_name = None
    blob_name = None
    # Track the outcome more granularly
    final_outcome_state = "processing_started"

    # --- Basic Checks ---
    if not storage_client:
        print("CRITICAL ERROR: Storage client failed to initialize. Aborting.")
        # Cannot proceed without storage access
        # Potentially raise an exception to signal failure clearly in logs
        return

    if not GTI_APIKEY:
        print("CRITICAL ERROR: GTI_APIKEY environment variable not set or empty. Aborting.")
        # Cannot proceed without API key
        return

    # --- Event Data Parsing ---
    try:
        if not event_data:
            print("ERROR: No data received in cloud_event.")
            final_outcome_state = "error_no_event_data"
            return

        source_bucket_name = event_data["bucket"]
        blob_name = event_data["name"]
        # Handle potential nested folders in blob name if necessary
        if not source_bucket_name or not blob_name:
             raise ValueError("Bucket name or blob name missing in event data.")

        print(f"Processing file: gs://{source_bucket_name}/{blob_name}")
        final_outcome_state = "event_data_parsed"

    except Exception as e:
        print(f"ERROR: Failed parsing event data: {e}")
        print(f"Received data: {json.dumps(event_data)}")
        final_outcome_state = "error_parsing_event_data"
        return

    # --- Initialize State Variables ---
    upload_successful = False
    analysis_id = None
    file_sha256 = None

    # --- Step 1: Upload to GTI/VirusTotal Private Scanning ---
    try:
        final_outcome_state = "upload_started"
        source_bucket = storage_client.bucket(source_bucket_name)
        source_blob = source_bucket.blob(blob_name)

        # Check existence before download/upload attempt
        source_blob.reload() # Raises NotFoundError if missing

        content_type = source_blob.content_type or 'application/octet-stream'

        payload = {
            "disable_sandbox": GTI_DISABLE_SANDBOX, "intercept_tls": GTI_INTERCEPT_TLS,
            "retention_period_days": GTI_RETENTION_DAYS, "storage_region": GTI_STORAGE_REGION,
            "locale": GTI_LOCALE, "enable_internet": GTI_ENABLE_INTERNET
        }
        payload = {k: v for k, v in payload.items() if v is not None} # Filter nulls if any

        upload_headers = {"accept": "application/json", "x-apikey": GTI_APIKEY}

        with source_blob.open("rb") as file_obj:
            files = {"file": (os.path.basename(blob_name), file_obj, content_type)} # Use basename
            print(f"Uploading {blob_name} ({content_type})... Payload: {payload}")
            response = requests.post(
                GTI_API_URL_PRIVATE_FILES_UPLOAD, data=payload, files=files,
                headers=upload_headers, timeout=180 # 3 min timeout for upload
            )
        response.raise_for_status() # Check for HTTP errors first
        response_json = response.json()

        # Verify expected response structure
        analysis_data = response_json.get("data", {})
        if analysis_data.get("type") == "private_analysis" and "id" in analysis_data:
            analysis_id = analysis_data["id"]
            print(f"Upload successful. Analysis ID: {analysis_id}")
            upload_successful = True
            final_outcome_state = "upload_successful"
        else:
             print(f"ERROR: Unexpected upload response format: {response_json}")
             final_outcome_state = "error_upload_bad_response"

    except storage.exceptions.NotFound:
         print(f"ERROR: Source blob gs://{source_bucket_name}/{blob_name} not found during upload attempt.")
         final_outcome_state = "error_source_blob_missing_on_upload"
         return # Cannot proceed if file vanished
    except requests.exceptions.RequestException as e:
        print(f"ERROR: GTI API request failed (Upload): {e}")
        if e.response is not None: print(f"Response status: {e.response.status_code}, Body: {e.response.text}")
        final_outcome_state = "error_upload_api_exception"
    except Exception as e:
        print(f"ERROR during file download/upload preparation: {e}")
        traceback.print_exc() # Uncomment for debugging
        final_outcome_state = "error_upload_general_exception"

    if not upload_successful or not analysis_id:
        print("Failed to initiate GTI Private Scanning analysis. File remains in new bucket for review.")
        # final_outcome_state already set appropriately above
        # Log final state before exiting
        end_processing_time = time.time()
        print(f"Processing finished for gs://{source_bucket_name}/{blob_name}. Final outcome state: {final_outcome_state}. Duration: {end_processing_time - start_processing_time:.2f}s")
        return

    # --- Step 2: Poll GTI Private Analysis for Results ---
    start_poll_time = time.time()
    analysis_complete = False
    final_outcome_state = "polling_started"
    poll_headers = {"accept": "application/json", "x-apikey": GTI_APIKEY}

    while time.time() - start_poll_time < MAX_POLL_TIME_SECONDS:
        try:
            poll_url = GTI_API_URL_PRIVATE_ANALYSES.format(analysis_id)
            response = requests.get(poll_url, headers=poll_headers, timeout=30)
            response.raise_for_status()
            result = response.json()
            status = result.get("data", {}).get("attributes", {}).get("status")

            if status == "completed":
                print("GTI Private Analysis completed.")
                final_outcome_state = "analysis_completed"
                analysis_complete = True
                # --- Corrected SHA256 Extraction ---
                try:
                    file_sha256 = result.get("meta", {}).get("file_info", {}).get("sha256")
                    if file_sha256:
                        print(f" Extracted SHA256: {file_sha256}")
                        final_outcome_state = "sha256_extracted"
                    else:
                        print("  ERROR: 'sha256' key not found in expected location ('meta.file_info.sha256').")
                        print(f"  Received analysis data structure (keys): {result.keys()}")
                        final_outcome_state = "error_parsing_sha256"
                        # file_sha256 remains None
                except Exception as e:
                    print(f"  ERROR: Exception while trying to extract SHA256: {e}")
                    final_outcome_state = "error_extracting_sha256_exception"
                    file_sha256 = None # Ensure it's None on error
                # --- End SHA256 Extraction ---
                break # Exit polling loop

            elif status in ["queued", "in-progress"]:
                print(f" Analysis status: {status}. Waiting {POLL_INTERVAL_SECONDS}s...")
                final_outcome_state = f"polling_status_{status}"
                time.sleep(POLL_INTERVAL_SECONDS)
            else:
                print(f"ERROR: Unexpected GTI analysis status: {status}. Result: {json.dumps(result)}")
                final_outcome_state = f"error_analysis_bad_status_{status}"
                analysis_complete = True # Stop polling on unexpected terminal status
                break

        except requests.exceptions.RequestException as e:
            print(f"ERROR: GTI API request failed (Polling): {e}")
            if e.response is not None: print(f"Response status: {e.response.status_code}, Body: {e.response.text}")
            print(f"Waiting {POLL_INTERVAL_SECONDS * 2}s before retrying poll...")
            final_outcome_state = "error_polling_api_exception_retrying"
            time.sleep(POLL_INTERVAL_SECONDS * 2) # Wait longer on API errors
        except Exception as e:
             print(f"ERROR during polling loop logic: {e}")
             final_outcome_state = "error_polling_general_exception"
             analysis_complete = True # Stop polling on other errors
             break

    if not analysis_complete and not final_outcome_state.startswith("error_"): # Check if polling timed out
         print(f"ERROR: GTI analysis did not complete within timeout ({MAX_POLL_TIME_SECONDS}s).")
         final_outcome_state = "error_polling_timeout"

    # --- Step 3: Get File Info / Verdict using SHA256 ---
    if file_sha256:
        print(f"Querying file info using SHA256: {file_sha256}...")
        final_outcome_state = "file_info_lookup_started"
        try:
            file_info_url = GTI_API_URL_PRIVATE_FILES_INFO.format(file_sha256)
            file_info_headers = {
                "accept": "application/json",
                "x-apikey": GTI_APIKEY,
                "x-tool": GTI_TOOL_NAME
            }
            response = requests.get(file_info_url, headers=file_info_headers, timeout=60)
            response.raise_for_status()
            file_info_result = response.json()

            # Extract verdict safely
            verdict = file_info_result.get("data", {}).get("attributes", {}).get("gti_assessment", {}).get("verdict", {}).get("value")

            if verdict:
                print(f"GTI Assessment Verdict: {verdict}")
                move_successful = False
                if verdict == "VERDICT_UNDETECTED":
                    final_outcome_state = "verdict_clean_moving"
                    move_successful = move_blob(source_bucket_name, blob_name, ALLOW_BUCKET_NAME)
                    final_outcome_state = "verdict_clean_moved" if move_successful else "error_move_allow_failed"
                elif verdict == "VERDICT_MALICIOUS":
                    final_outcome_state = "verdict_malicious_moving"
                    move_successful = move_blob(source_bucket_name, blob_name, QUARANTINE_BUCKET_NAME)
                    final_outcome_state = "verdict_malicious_moved" if move_successful else "error_move_quarantine_failed"
                elif verdict == "VERDICT_SUSPICIOUS":
                    print("Verdict is SUSPICIOUS - moving to quarantine for safety.")
                    final_outcome_state = "verdict_suspicious_moving"
                    move_successful = move_blob(source_bucket_name, blob_name, QUARANTINE_BUCKET_NAME)
                    final_outcome_state = "verdict_suspicious_moved" if move_successful else "error_move_quarantine_failed"
                else:
                    print(f"Unknown verdict value received: {verdict}")
                    final_outcome_state = f"error_unknown_verdict_{verdict}"
                    print(f"File {blob_name} stays in {source_bucket_name} due to unknown verdict.")
            else:
                print("ERROR: Could not find verdict ('data.attributes.gti_assessment.verdict.value') in file info response.")
                print(f" Received file info data (first 500 chars): {json.dumps(file_info_result)[:500]}")
                final_outcome_state = "error_parsing_verdict"
                print(f"File {blob_name} stays in {source_bucket_name} due to parsing error.")

        except requests.exceptions.RequestException as e:
            print(f"ERROR: GTI API request failed (File Info Lookup): {e}")
            if e.response is not None: print(f"Response status: {e.response.status_code}, Body: {e.response.text}")
            final_outcome_state = "error_api_file_info"
            print(f"File {blob_name} stays in {source_bucket_name} due to API error.")
        except Exception as e:
            print(f"ERROR during file info lookup or moving: {e}")
            traceback.print_exc() # Uncomment for debugging
            final_outcome_state = "error_exception_file_info_or_move"
            print(f"File {blob_name} may remain in {source_bucket_name} due to exception.")

    else:
        # Handle cases where polling failed or SHA256 couldn't be extracted
        print(f"File {blob_name} processing did not yield a SHA256. State before verdict step: {final_outcome_state}.")
        # Ensure state reflects the earlier failure if file_sha256 is None and state wasn't already error
        if not final_outcome_state.startswith("error_"):
             final_outcome_state = "error_sha256_not_available"
        print(f"File {blob_name} stays in {source_bucket_name} for review.")

    # --- Final Logging ---
    end_processing_time = time.time()
    print(f"Processing finished for gs://{source_bucket_name}/{blob_name}. Final outcome state: {final_outcome_state}. Duration: {end_processing_time - start_processing_time:.2f}s")
