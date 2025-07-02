import os
import requests
import json
from datetime import datetime
from google.cloud import storage, secretmanager
import pytz

def get_gti_api_key(project_id, secret_name):
    """Fetches the GTI API key from Secret Manager."""
    client = secretmanager.SecretManagerServiceClient()
    secret_version_name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
    response = client.access_secret_version(request={"name": secret_version_name})
    return response.payload.data.decode("UTF-8")

def gcs_upload(bucket_name, blob_name, data):
    """Uploads string data to a GCS bucket."""
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    blob.upload_from_string(data, content_type="application/json")
    print(f"File {blob_name} uploaded to {bucket_name}.")

def fetch_and_store_gti_data(request):
    """
    Main Cloud Function to fetch data from GTI, de-duplicate based on the latest timestamp,
    reshape it, and store it in GCS.
    """
    # ... (environment variable and API key fetching code is the same) ...
    try:
        project_id = os.environ.get("GCP_PROJECT")
        bucket_name = os.environ.get("BUCKET_NAME")
        secret_name = os.environ.get("SECRET_NAME")
    except Exception as e:
        print(f"Error reading environment variables: {e}")
        return ("Internal Server Error: Missing environment variables.", 500)

    try:
        api_key = get_gti_api_key(project_id, secret_name)
    except Exception as e:
        print(f"Error fetching API key: {e}")
        return ("Internal Server Error: Could not fetch API key.", 500)

    url = "https://www.virustotal.com/api/v3/threat_lists/infostealer/latest?&format=json"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "x-tool": "gcp_gti_pipeline-infostealer"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        api_data = response.json()
        
        # --- INTELLIGENT DE-DUPLICATION LOGIC ---
        unique_iocs = {}
        for item in api_data.get('iocs', []):
            ioc_data = item.get('data', {})
            ioc_id = ioc_data.get('id')
            
            if not ioc_id:
                continue

            # Get the timestamp for comparison. Default to 0 if missing.
            current_mod_date = ioc_data.get('attributes', {}).get('last_modification_date', 0)
            
            # If we haven't seen this ID, or if the new one is more recent, store it.
            if ioc_id not in unique_iocs or current_mod_date > unique_iocs[ioc_id].get('attributes', {}).get('last_modification_date', 0):
                unique_iocs[ioc_id] = ioc_data
        
        # --- END OF INTELLIGENT DE-DUPLICATION LOGIC ---

        # The reshaping logic remains the same, but now operates on the de-duplicated data
        reshaped_iocs = []
        for ioc_id, data in unique_iocs.items():
            attributes = data.get('attributes', {})
            new_ioc = {
                "ioc_id": ioc_id,
                "ioc_type": data.get('type'),
                "md5": attributes.get('md5'),
                "vhash": attributes.get('vhash'),
                "meaningful_name": attributes.get('meaningful_name'),
                "names": attributes.get('names'),
                "type_tags": attributes.get('type_tags'),
                "positives": attributes.get('positives'),
                "times_submitted": attributes.get('times_submitted'),
                "creation_date": attributes.get('creation_date'),
                "first_submission_date": attributes.get('first_submission_date'),
                "last_submission_date": attributes.get('last_submission_date'),
                "last_analysis_date": attributes.get('last_analysis_date'),
                "last_modification_date": attributes.get('last_modification_date'),
                "last_analysis_stats_harmless": attributes.get('last_analysis_stats', {}).get('harmless'),
                "last_analysis_stats_malicious": attributes.get('last_analysis_stats', {}).get('malicious'),
                "last_analysis_stats_suspicious": attributes.get('last_analysis_stats', {}).get('suspicious'),
                "last_analysis_stats_undetected": attributes.get('last_analysis_stats', {}).get('undetected'),
                "last_analysis_stats_timeout": attributes.get('last_analysis_stats', {}).get('timeout'),
                "last_analysis_stats_typeUnsupported": attributes.get('last_analysis_stats', {}).get('typeUnsupported'),
                "gti_assessment_severity": attributes.get('gti_assessment', {}).get('severity', {}).get('value'),
                "gti_assessment_threat_score": attributes.get('gti_assessment', {}).get('threat_score', {}).get('value'),
                "gti_assessment_verdict": attributes.get('gti_assessment', {}).get('verdict', {}).get('value'),
                "relationships": data.get('relationships')
            }
            reshaped_iocs.append(new_ioc)
        
        # 3. Convert the final list of dictionaries to an NDJSON string
        ndjson_data = "\n".join(json.dumps(ioc) for ioc in reshaped_iocs)

    except (requests.exceptions.RequestException, json.JSONDecodeError, KeyError) as e:
        print(f"Error processing data: {e}")
        return ("Internal Server Error: Could not process API response.", 500)

    sgt_timezone = pytz.timezone('Asia/Singapore')
    now_in_sgt = datetime.now(sgt_timezone)
    blob_name = f"gti_responses/{now_in_sgt.strftime('%Y-%m-%d')}/{now_in_sgt.strftime('%H-%M-%S')}.json"

    try:
        gcs_upload(bucket_name, blob_name, ndjson_data)
    except Exception as e:
        print(f"Error uploading to GCS: {e}")
        return ("Internal Server Error: GCS upload failed.", 500)
        
    return (f"Successfully fetched, de-duplicated, and stored GTI data to {blob_name}.", 200)