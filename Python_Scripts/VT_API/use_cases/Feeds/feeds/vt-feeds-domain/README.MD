## WIP

using vt-domains. calling per minute as per hour is too large and too consuming. unsure if it will meet cloud function limit. 
to save on unnecessary compute and costs, doing batch jobs
fetch every 10 mins, with the script calling delta of 1 hour + 10 mins back. 
eg, 1520 UTC now. the feed_time is 1410 UTC, and will call 1410, 1411, 1412 ... 1419
merge funciton will run every 30 minutes. 

This introduces some problems. 
the original load script from the gti-threat-list is based on write.truncate, which basically wipes the staging database out every time. we could do that as we're running it hourly, and we're not consuming crazy resources for the purpose of lab/poc. 

however, for domains, since running per hour jobs does timeout, we had to batch it. this can cause a slight challenge: 
1100 - merge function completes
1110 - fetch function runs, and saves ioc_1 and ioc_2 on file1.json
1120 - fetch function runes, and saves ioc_1 and ioc_3 on file2.json. 

with truncate, we basically clear everything from the 1110 fetch, and we'll lose ioc_2. 

solution is to dedup on the fly. using the most recent ioc based on last_analysed_date.

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

Load function is changed due to how we're batch running the job. 
since we are running the fetch every 10 mins and merging only every 30 mins

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

create scheduler for every 10 minutes. notice the "*/" in the schedule. this indicates for it to run every 10 mins. 

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

```bash
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="'$FETCH_FUNCTION_NAME'"' --limit=20
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="'$FETCH_FUNCTION_NAME'"' --limit=20 --format='value(textPayload)'

gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="'$MERGE_FUNCTION_NAME'"' --limit=20 --format='value(textPayload)'
```

Encountered out of memory error
```bash
[2025-07-05 17:21:16 +0000] [1] [ERROR] Worker (pid:13) was sent SIGKILL! Perhaps out of memory?
Out-of-memory event detected in container
```

Since vt feeds are much bigger vs gti-threat-lists, when the function unzip the entire data it attempted to load it into memory before uploading it. we needed a better way, so we turned to streaming the data, without ever having to hold the entire chuck in memory. 

