# Use this simpler, memory-efficient version for your fetch function's main.py
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


def fetch_and_stream_feed(request):
    try:
        project_id = os.environ.get("GCP_PROJECT")
        bucket_name = os.environ.get("BUCKET_NAME")
        secret_name = os.environ.get("SECRET_NAME")
        api_key = get_gti_api_key(project_id, secret_name)
    except Exception as e:
        print(f"Error getting config: {e}")
        return ("Internal Server Error", 500)

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    base_time_utc = datetime.now(timezone.utc)

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
                    continue

                blob_name = f"domain-feeds/{feed_time}.jsonl"
                blob = bucket.blob(blob_name)

                with requests.get(download_url, stream=True) as file_response:
                    file_response.raise_for_status()
                    decompressor = bz2.BZ2Decompressor()
                    with blob.open("wb") as gcs_file:
                        for chunk in file_response.iter_content(chunk_size=8192):
                            decompressed_chunk = decompressor.decompress(chunk)
                            gcs_file.write(decompressed_chunk)
                
                print(f"Successfully streamed {blob_name} to {bucket_name}.")

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