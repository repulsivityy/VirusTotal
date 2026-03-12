import os
import requests
import bz2
import logging
import time
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.cloud import storage, secretmanager
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class Settings:
    """Centralized environment variables management."""
    def __init__(self):
        self.project_id = os.environ.get("GCP_PROJECT")
        self.bucket_name = os.environ.get("BUCKET_NAME")
        self.secret_name = os.environ.get("SECRET_NAME")
        self.feed_type = os.environ.get("FEED_TYPE", "files") # Default to files for hash feeds
        
        if not all([self.project_id, self.bucket_name, self.secret_name]):
            raise ValueError("Missing essential environment variables: GCP_PROJECT, BUCKET_NAME, SECRET_NAME")

def get_api_key(project_id, secret_name):
    """Retrieves API key from Secret Manager."""
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
    try:
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        logger.error(f"Failed to access secret {secret_name}: {e}")
        raise

def get_session():
    """Returns a requests Session with retry logic."""
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session

def fetch_single_minute(session, api_key, feed_time, bucket, feed_type):
    """Fetches a single minute of feed data and streams it to GCS."""
    api_url = f"https://www.virustotal.com/api/v3/feeds/{feed_type}/{feed_time}"
    headers = {"x-apikey": api_key}
    
    try:
        logger.info(f"Fetching {feed_type} feed for time: {feed_time}")
        # allow_redirects=False to handle the 302 signed URL properly
        initial_response = session.get(api_url, headers=headers, allow_redirects=False, timeout=10)
        initial_response.raise_for_status()

        if initial_response.status_code == 302:
            download_url = initial_response.headers.get('Location')
            if not download_url:
                logger.warning(f"302 response for {feed_time} missing Location header.")
                return False

            blob_name = f"{feed_type}-feeds/{feed_time}.jsonl"
            blob = bucket.blob(blob_name)

            with session.get(download_url, stream=True, timeout=30) as file_response:
                file_response.raise_for_status()
                decompressor = bz2.BZ2Decompressor()
                with blob.open("wb") as gcs_file:
                    for chunk in file_response.iter_content(chunk_size=65536): # Increased chunk size for better throughput
                        if chunk:
                            decompressed_chunk = decompressor.decompress(chunk)
                            gcs_file.write(decompressed_chunk)
            
            logger.info(f"Successfully streamed {blob_name} to GCS.")
            return True

        else:
            logger.warning(f"Expected 302 for {feed_time}, got {initial_response.status_code}. Skipping.")
            return False

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.info(f"No feed found for {feed_time} (404), skipping.")
        else:
            logger.error(f"HTTP Error for {feed_time}: {e}.")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred for {feed_time}: {e}")
        return False

def fetch_and_stream_hash_feed(request):
    """Main entry point for Cloud Function."""
    try:
        settings = Settings()
        api_key = get_api_key(settings.project_id, settings.secret_name)
    except Exception as e:
        logger.critical(f"Initialization failed: {e}")
        return ("Internal Server Error", 500)

    storage_client = storage.Client()
    bucket = storage_client.bucket(settings.bucket_name)
    session = get_session()
    
    base_time_utc = datetime.now(timezone.utc)
    # Target window: last 10 minutes, offset by 1 hour (as per original logic)
    feed_times = []
    for i in range(10, 0, -1):
        target_time = base_time_utc - timedelta(hours=1) - timedelta(minutes=i)
        feed_times.append(target_time.strftime('%Y%m%d%H%M'))

    logger.info(f"Starting batch fetch for {len(feed_times)} minutes.")

    # Optimized with ThreadPoolExecutor for parallel fetching
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_time = {
            executor.submit(fetch_single_minute, session, api_key, ft, bucket, settings.feed_type): ft 
            for ft in feed_times
        }
        for future in as_completed(future_to_time):
            ft = future_to_time[future]
            try:
                success = future.result()
                results.append(success)
            except Exception as e:
                logger.error(f"Thread failed for {ft}: {e}")
                results.append(False)

    success_count = sum(results)
    logger.info(f"Batch fetch complete. Successfully processed {success_count}/{len(feed_times)} minutes.")

    return (f"Processed {success_count}/{len(feed_times)} files.", 200)
