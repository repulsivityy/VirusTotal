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
    Main Cloud Function to fetch data from GTI, reshape it to match the BQ schema,
    convert it to NDJSON, and store it in GCS.
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


    url = "https://www.virustotal.com/api/v3/threat_lists/malicious-network-infrastructure/latest?&type=url&format=json"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "x-tool": "gcp_gti_pipeline"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        api_data = response.json()
        
        # --- FINAL JSON TRANSFORMATION LOGIC ---
        reshaped_iocs = []
        for item in api_data.get('iocs', []):
            # Start with the attributes dictionary, which has most of our fields
            # Use .get() to avoid errors if a key is missing
            attributes = item.get('data', {}).get('attributes', {})
            
            # Create a new dictionary that matches the BQ schema
            new_ioc = {
                "ioc_id": item.get('data', {}).get('id'),
                "ioc_type": item.get('data', {}).get('type'),
                "url": attributes.get('url'),
                "tld": attributes.get('tld'),
                "positives": attributes.get('positives'),
                "times_submitted": attributes.get('times_submitted'),
                "first_submission_date": attributes.get('first_submission_date'),
                "last_submission_date": attributes.get('last_submission_date'),
                "last_analysis_date": attributes.get('last_analysis_date'),
                "last_modification_date": attributes.get('last_modification_date'),
                "last_analysis_stats_harmless": attributes.get('last_analysis_stats', {}).get('harmless'),
                "last_analysis_stats_malicious": attributes.get('last_analysis_stats', {}).get('malicious'),
                "last_analysis_stats_suspicious": attributes.get('last_analysis_stats', {}).get('suspicious'),
                "last_analysis_stats_undetected": attributes.get('last_analysis_stats', {}).get('undetected'),
                "gti_assessment_severity": attributes.get('gti_assessment', {}).get('severity', {}).get('value'),
                "gti_assessment_threat_score": attributes.get('gti_assessment', {}).get('threat_score', {}).get('value'),
                "gti_assessment_verdict": attributes.get('gti_assessment', {}).get('verdict', {}).get('value'),
                "categories": attributes.get('categories'),
                "relationships": item.get('data', {}).get('relationships') # Keep the whole relationships object
            }
            reshaped_iocs.append(new_ioc)
        
        # Convert the list of reshaped dictionaries to an NDJSON string
        ndjson_data = "\n".join(json.dumps(ioc) for ioc in reshaped_iocs)
        # --- END OF TRANSFORMATION LOGIC ---

    except requests.exceptions.RequestException as e:
        print(f"Error calling GTI API: {e}")
        return ("Internal Server Error: API call failed.", 502)
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error parsing JSON response: {e}")
        return ("Internal Server Error: Could not parse API response.", 500)

    # ... (timestamp generation and GCS upload code is the same) ...
    sgt_timezone = pytz.timezone('Asia/Singapore')
    now_in_sgt = datetime.now(sgt_timezone)
    blob_name = f"gti_responses/{now_in_sgt.strftime('%Y-%m-%d')}/{now_in_sgt.strftime('%H-%M-%S')}.json"

    try:
        gcs_upload(bucket_name, blob_name, ndjson_data)
    except Exception as e:
        print(f"Error uploading to GCS: {e}")
        return ("Internal Server Error: GCS upload failed.", 500)
        
    return (f"Successfully fetched, reshaped, and stored GTI data to {blob_name}.", 200)