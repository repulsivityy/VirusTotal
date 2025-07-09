# VirusTotal Domain Feeds - Threat Intelligence Pipeline

Serverless, automated data pipeline runs on Google Cloud. It runs hourly to fetch domain feeds from VirusTotal / Google Threat Intelligence API and ingests them into Google Big Query. 

## Architecture Overview
The pipeline follows a proven event-driven model:

1. **Cloud Scheduler (Fetch):** A cron job (*/10 * * * *) triggers the pipeline every 10 minutes.
2. **Cloud Function (Fetch Domains):** Fetches the last 10 minutes of domain feeds from the GTI API, using a memory-efficient streaming process to upload the raw data directly to a Cloud Storage bucket.
3. **Cloud Storage Bucket:** A landing zone for the raw, newline-delimited JSON (NDJSON) files.
4. **Cloud Function (Load to Staging):** Triggered by new files in the bucket, this function appends the data into a BigQuery "staging" table.
5. **Cloud Scheduler (Merge):** A second cron job (5,35 * * * *) runs every 30 minutes to trigger the merge process.
6. **Cloud Function (Execute Merge):** This function runs a "smart" MERGE query that de-duplicates the staging table on the fly before updating the final production table. It then truncates the staging table.
7. **BigQuery:** Hosts the staging table and the final, de-duplicated domains table, ready for analysis and machine learning models.

---

## Deployment

Deployment mainly follows the same architectural design as the [gti-threatlist](https://github.com/repulsivityy/VirusTotal/blob/main/Python_Scripts/VT_API/use_cases/gti_threatlist_bq/malicious_network_infra_urls/README_malicious_urls.MD) deployment. Below are key items that's necessary / tweaked for this deployment. 

### Env Var

```bash
export GCP_PROJECT_ID="vt-data-lake"
export GCP_REGION="asia-southeast1" # Or your preferred region
export SERVICE_ACCOUNT_NAME="gti-pipeline-sa"
export SCHEDULER_SA_NAME="gti-scheduler-invoker"
export THREAT_LIST="vt-domain-feed"
export BUCKET_NAME="gti-ioc-responses-${THREAT_LIST}-${GCP_PROJECT_ID}"
export BQ_DATASET_NAME="vt_feeds" 
export BQ_TABLE_NAME="${THREAT_LIST}"
export BQ_STAGING_TABLE_NAME="${THREAT_LIST}_staging"
export SECRET_NAME="gti-api-key"
export FETCH_FUNCTION_NAME="gti-fetch-iocs-${THREAT_LIST}"
export LOAD_FUNCTION_NAME="gti-load-data-${THREAT_LIST}"
export MERGE_FUNCTION_NAME="gti-execute-merge-${THREAT_LIST}"
export FETCH_SCHEDULER_NAME="gti-hourly-trigger-${THREAT_LIST}"
export MERGE_SCHEDULER_NAME="gti-hourly-merge-${THREAT_LIST}"
```


Make sure to update the entry point to match what you created in the main.py

```bash
gcloud functions deploy $FETCH_FUNCTION_NAME \
  --gen2 \
  --runtime=python311 \
  --region=$GCP_REGION \
  --source=. \
  --entry-point=fetch_and_stream_feed \
  --trigger-http \
  --no-allow-unauthenticated \
  --service-account=$SERVICE_ACCOUNT_EMAIL \
  --set-env-vars=GCP_PROJECT=$GCP_PROJECT_ID,BUCKET_NAME=$BUCKET_NAME,SECRET_NAME=$SECRET_NAME
```

Load function is changed due to how we're batch running the job since we are running the fetch every 10 mins and merging only every 30 mins

```bash
gcloud functions deploy $MERGE_FUNCTION_NAME \
  --gen2 \
  --runtime=python311 \
  --region=$GCP_REGION \
  --source=. \
  --entry-point=execute_bigquery_merge \
  --trigger-http \
  --no-allow-unauthenticated \
  --service-account=$SERVICE_ACCOUNT_EMAIL \
  --set-env-vars=GCP_PROJECT=$GCP_PROJECT_ID,BQ_DATASET_NAME=$BQ_DATASET_NAME,BQ_TABLE_NAME=$BQ_TABLE_NAME,BQ_STAGING_TABLE_NAME=$BQ_STAGING_TABLE_NAME
```

Create scheduler for every 10 minutes. notice the "*/" in the schedule. this indicates for it to run every 10 mins. 

```bash
gcloud scheduler jobs create http $FETCH_SCHEDULER_NAME \
  --location=$GCP_REGION \
  --schedule="*/10 * * * *" \
  --uri=$FETCH_FUNCTION_URL \
  --http-method=POST \
  --oidc-service-account-email=$SCHEDULER_SA_EMAIL
```

Runs at 5 minutes and 35 minutes past every hour 
```bash
gcloud scheduler jobs create http $MERGE_SCHEDULER_NAME \
  --location=$GCP_REGION \
  --schedule="5,35 * * * *" \
  --uri=$MERGE_FUNCTION_URL \
  --http-method=POST \
  --oidc-service-account-email=$SCHEDULER_SA_EMAIL
```

## Troubleshooting 

```bash
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="'$FETCH_FUNCTION_NAME'"' --limit=20
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="'$FETCH_FUNCTION_NAME'"' --limit=20 --format='value(textPayload)'

gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="'$MERGE_FUNCTION_NAME'"' --limit=20 --format='value(textPayload)'
```

### Tips / Challenges faced. 

When calling VT Domains, changed to call per minute as the per hour API call is too large and too resource intensive. Also, I wasn't sure if it will burst Cloud Function's limit. 
To save on unnecessary compute and costs, decided to do batch jobs, with the logic as such: 
- fetch every 10 mins, with the script calling delta of 1 hour + 10 mins back. 
  - eg, 1520 UTC now. the feed_time is 1410 UTC, and will call 1410, 1411, 1412 ... 1419
- merge function will run every 30 minutes. 

This introduces some problems.

#### Problem 1
The original load script from the gti-threat-list is based on write.truncate, which basically wipes the staging database out every time. We could do that as we're running it hourly for threat-lists, and we're not consuming crazy resources for the purpose of lab/poc. 

However, for domains, since running per hour jobs does timeout, we had to batch it. this can cause a slight challenge: 
- 1100 - merge function completes
- 1110 - fetch function runs, and saves ioc_1 and ioc_2 on file1.json
- 1120 - fetch function runes, and saves ioc_1 and ioc_3 on file2.json. 

With truncate, we basically clear everything from the 1110 fetch, and we'll lose ioc_2. 

With some google-fu and gemini-fu, the solution is to dedup on the fly. using the most recent ioc based on last_analysed_date.

```bash
MERGE `project.dataset.domains` T
USING (
  -- De-duplicate the source on-the-fly
  SELECT * FROM `project.dataset.staging_domains`
  QUALIFY ROW_NUMBER() OVER(PARTITION BY id ORDER BY attributes.last_analysis_date DESC) = 1
) S
ON T.id = S.id
WHEN MATCHED THEN ...
WHEN NOT MATCHED THEN ...
```

#### Problem 2

Encountered out of memory error
```bash
[2025-07-05 17:21:16 +0000] [1] [ERROR] Worker (pid:13) was sent SIGKILL! Perhaps out of memory?
Out-of-memory event detected in container
```

Since vt feeds are much bigger vs gti-threat-lists, when the function unzip the entire data it attempted to load it into memory before uploading it. we needed a better way, so we turned to streaming the data, without ever having to hold the entire chuck in memory. Used `requests.get(stream=True)` to download the feed in small chunks. Each chunk is decompressed on-the-fly and written directly to a GCS blob stream via `blob.open("wb")`

```bash
with requests.get(download_url, stream=True) as file_response:
  file_response.raise_for_status()
  decompressor = bz2.BZ2Decompressor()
  with blob.open("wb") as gcs_file:
      for chunk in file_response.iter_content(chunk_size=8192):
          decompressed_chunk = decompressor.decompress(chunk)
          gcs_file.write(decompressed_chunk)
```
