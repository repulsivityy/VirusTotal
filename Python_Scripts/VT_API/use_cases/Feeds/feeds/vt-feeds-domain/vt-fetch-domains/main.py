import os
import requests
import bz2
from datetime import datetime, timezone, timedelta
from google.cloud import storage, secretmanager
import time

def get_gti_api_key(project_id, secret_name):
    client = secretmanager.SecretManagerServiceClient()
    secret_version_name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
    response = client.access_secret_version(request={"name": secret_version_name})
    return response.payload.data.decode("UTF-8")

def gcs_upload(bucket_name, blob_name, data):
    """Uploads bytes data to a GCS bucket."""
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    blob.upload_from_string(data, content_type="application/octet-stream")
    print(f"File {blob_name} uploaded to {bucket_name}.")


def fetch_and_stream_feed(request):
    """
    Fetches a 10-minute block of feeds with a 1-hour offset, in chronological order.
    """
    try:
        project_id = os.environ.get("GCP_PROJECT")
        bucket_name = os.environ.get("BUCKET_NAME")
        secret_name = os.environ.get("SECRET_NAME")
        api_key = get_gti_api_key(project_id, secret_name)
    except Exception as e:
        print(f"Error getting config: {e}")
        return ("Internal Server Error", 500)

    base_time_utc = datetime.now(timezone.utc)

    # Loop from 10 down to 1 to fetch oldest data first.
    for i in range(10, 0, -1):
        
        target_time = base_time_utc - timedelta(hours=1) - timedelta(minutes=i)
        
        feed_time = target_time.strftime('%Y%m%d%H%M')
        
        api_url = f"https://www.virustotal.com/api/v3/feeds/domains/{feed_time}"
        headers = {"x-apikey": api_key}
        
        try:
            print(f"Fetching feed for time: {feed_time}")
            initial_response = requests.get(api_url, headers=headers, allow_redirects=False)
            initial_response.raise_for_status()

            if initial_response.status_code == 302:
                download_url = initial_response.headers.get('Location')
                if not download_url:
                    print(f"Warning: No Location header for {feed_time}, skipping.")
                    continue

                file_response = requests.get(download_url)
                file_response.raise_for_status()
                decompressed_data = bz2.decompress(file_response.content)

                blob_name = f"domain-feeds/{feed_time}.jsonl"
                gcs_upload(bucket_name, blob_name, decompressed_data)

            else:
                print(f"Warning: Expected 302 for {feed_time}, got {initial_response.status_code}. Skipping.")

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"No feed found for {feed_time} (404), skipping.")
            else:
                print(f"HTTP Error for {feed_time}: {e}. Skipping this minute.")
            continue
        except Exception as e:
            print(f"An error occurred for {feed_time}: {e}. Skipping this minute.")
            continue
        
        time.sleep(1) 

    return ("Batch fetch complete.", 200)