# GTI Threat Intelligence Pipeline

This project creates a serverless, automated data pipeline on Google Cloud. It fetches a list of malicious URLs hourly from the Google Threat Intelligence's Categorised Threat List via API, ingests the data into Google BigQuery, and maintains a de-duplicated, up-to-date dataset by merging new data with existing records. The entire process is event-driven and designed for reliability and low operational overhead.

---

## Architecture Overview

The pipeline uses a series of decoupled Google Cloud services that trigger each other to process the data. The high-level workflow is as follows:

1.  **`Cloud Scheduler (Fetch)`**: A cron job that triggers the pipeline every hour at 5 minutes past the hour.
2.  **`Cloud Function (gti-fetch-iocs)`**: An HTTP-triggered function that calls the GTI API, transforms the JSON response into newline-delimited JSON (NDJSON), and saves the file to a Cloud Storage bucket.
3.  **`Cloud Storage Bucket`**: A landing zone for the raw NDJSON files. The creation of a file in this bucket triggers the next step.
4.  **`Cloud Function (gti-load-data)`**: An event-driven function that loads the new NDJSON file from the bucket into a BigQuery "staging" table, overwriting it each time.
5.  **`Cloud Scheduler (Merge)`**: A second cron job that runs every hour at 15 minutes past the hour.
6.  **`Cloud Function (gti-execute-merge)`**: An HTTP-triggered function that runs a `MERGE` SQL query, intelligently updating the final BigQuery table with the data from the staging table.
7.  **`BigQuery`**: Contains the `staging` and final `malicious_urls` tables where the threat intelligence data is stored and is available for analysis.

---

## Prerequisites

Before you begin, ensure you have the following prerequisites in place:

* **Google Cloud Project**: You must have an active Google Cloud project with billing enabled.
* **Google Cloud SDK**: The `gcloud` command-line tool must be installed and configured on your local machine. You can find installation instructions [here](https://cloud.google.com/sdk/docs/install).
* **Authenticated `gcloud` CLI**: You need to be authenticated with the SDK. You can do this by running `gcloud auth login`.
* **Required Permissions**: For the one-time setup, your user account needs high-level permissions to create all the necessary resources. The **Project Owner** or **Project Editor** role is recommended.
* **GTI API Key**: You must have a valid API key from Google Threat Intelligence to access the threat intelligence feed.

---


## Deployment Guide

This guide provides all the necessary commands to deploy the entire pipeline from scratch.

### Step 1: Configuration & Setup

First, set the following environment variables in your shell. This will ensure consistency across all subsequent commands.

```bash
# --- Set Your Configuration Variables Here ---
export GCP_PROJECT_ID="your-gcp-project-id"
export GCP_REGION="asia-southeast1" # Or your preferred region
export SERVICE_ACCOUNT_NAME="gti-pipeline-sa"
export SCHEDULER_SA_NAME="gti-scheduler-invoker"
export THREAT_LIST="malicious_urls"
export BUCKET_NAME="gti-ioc-responses-${THREAT_LIST}-${GCP_PROJECT_ID}"
export BQ_DATASET_NAME="gti_threatintel_bq" 
export BQ_TABLE_NAME="${THREAT_LIST}"
export BQ_STAGING_TABLE_NAME="${THREAT_LIST}_staging"
export SECRET_NAME="gti-api-key"
export FETCH_FUNCTION_NAME="gti-fetch-iocs-${THREAT_LIST}"
export LOAD_FUNCTION_NAME="gti-load-data-${THREAT_LIST}"
export MERGE_FUNCTION_NAME="gti-execute-merge-${THREAT_LIST}"
export FETCH_SCHEDULER_NAME="gti-hourly-trigger-${THREAT_LIST}"
export MERGE_SCHEDULER_NAME="gti-hourly-merge-${THREAT_LIST}"

# --- Set Derived Variables (No need to edit these) ---
export SERVICE_ACCOUNT_EMAIL="${SERVICE_ACCOUNT_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
export SCHEDULER_SA_EMAIL="${SCHEDULER_SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

# --- Set the active project for gcloud ---
gcloud config set project $GCP_PROJECT_ID
```

Next, enable all the necessary Google Cloud APIs for your project.

```bash
gcloud services enable \
  iam.googleapis.com \
  secretmanager.googleapis.com \
  storage.googleapis.com \
  cloudbuild.googleapis.com \
  cloudfunctions.googleapis.com \
  bigquery.googleapis.com \
  cloudscheduler.googleapis.com \
  run.googleapis.com \
  eventarc.googleapis.com \
  pubsub.googleapis.com
```

### Step 2: Create Service Accounts & Secrets

Create the two dedicated service accounts required for the pipeline. One will be used by the Cloud Functions to interact with other Google Cloud services, and the other will be used by Cloud Scheduler to securely trigger the functions.

```bash
# Create the main pipeline service account
gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
  --display-name="GTI Data Pipeline Service Account"

# Create the service account for the scheduler to use for authenticated calls
gcloud iam service-accounts create $SCHEDULER_SA_NAME \
  --display-name="GTI Scheduler Invoker"
```

Next, create a secret in Secret Manager to securely store your GTI API Key. The command will prompt you to paste your key into the terminal.

```bash
# Create the secret container
gcloud secrets create $SECRET_NAME \
  --replication-policy="automatic"

# Add your API key as the first version of the secret
echo "Please paste your GTI API Key, then press Enter:"
read -s GTI_API_KEY_VALUE
echo -n "$GTI_API_KEY_VALUE" | gcloud secrets versions add $SECRET_NAME --data-file=-
echo "API Key has been securely stored in Secret Manager."
```

### Step 3: Create Infrastructure

#### Cloud Storage Bucket
Create the GCS bucket that will be used as a staging area for the raw data files from the GTI API.

```bash
gcloud storage buckets create gs://${BUCKET_NAME} --location=$GCP_REGION
```

Next, I created a lifecycle rule to automatically delete raw files after 7 days to manage costs and data retention, this is found in the file  `lifecycle.json`. Now, apply this rule to your bucket:

```bash
gcloud storage buckets update gs://${BUCKET_NAME} --lifecycle-file=./lifecycle.json
```

#### BigQuery Resources

Create the BigQuery dataset that will contain your tables
>Creating the dataset is not required if you've already built it

```bash
bq --location=$GCP_REGION mk --dataset $GCP_PROJECT_ID:$BQ_DATASET_NAME
```

Next, copy the file named `schema.json` into your main directory. This defines the structure for both of your BigQuery tables.

Finally, use the schema file to create the final production table and the temporary staging table.

```bash
# Create the final table
bq mk --table \
  --description="Final de-duplicated table for GTI ${THREAT_LIST} files" \
  $GCP_PROJECT_ID:$BQ_DATASET_NAME.$BQ_TABLE_NAME \
  ./schema_malicious_urls.json

# Create the staging table
bq mk --table \
  --description="Staging table for incoming GTI ${THREAT_LIST} files" \
  $GCP_PROJECT_ID:$BQ_DATASET_NAME.$BQ_STAGING_TABLE_NAME \
  ./schema_malicious_urls.json
```

### Step 4: Grant IAM Permissions

This section outlines the specific permissions needed for each service account to perform its role.

#### Permissions for the Main Pipeline Service Account

##### Permissions for BigQuery, SecretsManager, Eventarc
> only needs to be run once - if previously created not needed

Grant the `gti-pipeline-sa` service account the roles it needs to access secrets, create/read GCS objects, run BigQuery jobs, and receive events.

```bash
# Allow access to the API key in Secret Manager
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

# Allow the "Load" and "Merge" functions to run BigQuery jobs
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/bigquery.jobUser"

# Allow the "Load" function to be triggered by GCS events via Eventarc
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/eventarc.eventReceiver"
```

#### Permissions for the Scheduler Service Account
> This is needed for every new function / threat list deployed. 

```bash
# Allow the "Fetch" function to write files to the GCS bucket
gcloud storage buckets add-iam-policy-binding gs://${BUCKET_NAME} \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/storage.objectCreator"

# Allow the "Load" function to read files from the GCS bucket
gcloud storage buckets add-iam-policy-binding gs://${BUCKET_NAME} \
  --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
  --role="roles/storage.objectViewer"
```

#### Permissions for Google-Managed Service Accounts

Grant Google's own services the permissions they need to operate within the pipeline.
> Not needed if already created

```bash
# Find the unique service account for Cloud Storage in your project
GCS_SERVICE_ACCOUNT=$(gsutil kms serviceaccount -p $GCP_PROJECT_ID)

# Allow the Cloud Storage service to publish events to Pub/Sub for the GCS trigger
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
    --member="serviceAccount:${GCS_SERVICE_ACCOUNT}" \
    --role="roles/pubsub.publisher"
```

### Step 5: Deploy Cloud Functions

This section details the deployment for the three Cloud Functions that power the pipeline. For each function, you will create a directory, add the required code files, and then run a `gcloud` command to deploy it.

---
#### 5.1: The "Fetch" Function (`gti-fetch-iocs-malicious_urls`)
This function is triggered by a scheduler. It calls the GTI API, transforms the response to NDJSON, and saves it to the GCS bucket.

1.  **Create the directory and files:**
    ```bash
    mkdir gti-fetch-iocs
    ```
    Inside this new directory, create two files:
    * `main.py`: Add the Python code found in the `gti-fetch-iocs-malicious_urls/main.py` file of this repository.
    * `requirements.txt`: Add the content from `gti-fetch-iocs-malicious_urls/requirements.txt`.

2.  **Deploy the function:**
    ```bash
    # Make sure you are inside the gti-fetch-iocs-malicious_urls directory
    gcloud functions deploy $FETCH_FUNCTION_NAME \
      --gen2 \
      --runtime=python311 \
      --region=$GCP_REGION \
      --source=. \
      --entry-point=fetch_and_store_gti_data \
      --trigger-http \
      --no-allow-unauthenticated \
      --service-account=$SERVICE_ACCOUNT_EMAIL \
      --set-env-vars=GCP_PROJECT=$GCP_PROJECT_ID,BUCKET_NAME=$BUCKET_NAME,SECRET_NAME=$SECRET_NAME
    ```

---
#### 5.2: The "Load" Function (`gti-load-data-malicious_urls`)
This function is triggered by a new file landing in the GCS bucket. It loads the data from that file into the BigQuery staging table.

1.  **Create the directory and files:**
    ```bash
    cd ..
    mkdir gti-load-data-malicious_urls
    cd gti-load-data-malicious_urls
    ```
    Inside this new directory, create two files:
    * `main.py`: Add the Python code found in the `gti-load-data-malicious_urls/main.py` file of this repository.
    * `requirements.txt`: Add the content from `gti-load-data-malicious_urls/requirements.txt`.

2.  **Deploy the function:**
    ```bash
    # Make sure you are inside the gti-load-data directory
    gcloud functions deploy $LOAD_FUNCTION_NAME \
      --gen2 \
      --runtime=python311 \
      --region=$GCP_REGION \
      --source=. \
      --entry-point=gcs_to_bigquery_loader \
      --trigger-resource=$BUCKET_NAME \
      --trigger-event=google.storage.object.finalize \
      --service-account=$SERVICE_ACCOUNT_EMAIL \
      --set-env-vars=GCP_PROJECT=$GCP_PROJECT_ID,BQ_DATASET_NAME=$BQ_DATASET_NAME,BQ_STAGING_TABLE_NAME=$BQ_STAGING_TABLE_NAME
    ```

---
#### 5.3: The "Merge" Function (`gti-execute-merge-malicious_urls`)
This function is triggered by a scheduler. It runs the `MERGE` SQL query to update the final BigQuery table from the staging table.

1.  **Create the directory and files:**
    ```bash
    cd ..
    mkdir gti-execute-merge-malicious_urls
    cd gti-execute-merge-malicious_urls
    ```
    Inside this new directory, create two files:
    * `main.py`: Add the Python code found in the `gti-execute-merge-malicious_urls/main.py` file of this repository.
    * `requirements.txt`: Add the content from `gti-execute-merge-malicious_urls/requirements.txt`.

2.  **Deploy the function:**
    ```bash
    # Make sure you are inside the gti-execute-merge directory
    gcloud functions deploy $MERGE_FUNCTION_NAME \
      --gen2 \
      --runtime=python311 \
      --region=$GCP_REGION \
      --source=. \
      --entry-point=execute_bigquery_merge \
      --trigger-http \
      --no-allow-unauthenticated \
      --service-account=$SERVICE_ACCOUNT_EMAIL \
      --set-env-vars=GCP_PROJECT=$GCP_PROJECT_ID,BQ_DATASET_NAME=$BQ_DATASET_NAME
    ```

### Step 6: Create Schedulers

#### Permissions for the Scheulder Service Account
>This is needed for every new function / threat list deployed. 

Grant the gti-scheduler-invoker service account permission to call your private Cloud Functions.

```bash
# Allow the scheduler's invoker to call the "Fetch" function
gcloud functions add-invoker-policy-binding $FETCH_FUNCTION_NAME \
  --region=$GCP_REGION \
  --member="serviceAccount:${SCHEDULER_SA_EMAIL}"

# Allow the scheduler's invoker to call the "Merge" function
gcloud functions add-invoker-policy-binding $MERGE_FUNCTION_NAME \
  --region=$GCP_REGION \
  --member="serviceAccount:${SCHEDULER_SA_EMAIL}"
```

Finally, create the two scheduler jobs that trigger the "Fetch" and "Merge" functions on an hourly basis.

#### 6.1: The "Fetch" Scheduler
This job runs every hour at 5 minutes past the hour and calls the `gti-fetch-iocs-malicious_urls` function.

1.  **Get the URL of the "Fetch" function:**
    ```bash
    FETCH_FUNCTION_URL=$(gcloud functions describe $FETCH_FUNCTION_NAME --region=$GCP_REGION --gen2 --format='value(serviceConfig.uri)')
    ```
2.  **Create the scheduler job:**
    ```bash
    gcloud scheduler jobs create http $FETCH_SCHEDULER_NAME \
      --location=$GCP_REGION \
      --schedule="5 * * * *" \
      --uri=$FETCH_FUNCTION_URL \
      --http-method=POST \
      --oidc-service-account-email=$SCHEDULER_SA_EMAIL
    ```

---
#### 6.2: The "Merge" Scheduler
This job runs every hour at 15 minutes past the hour, giving the fetch-and-load process plenty of time to complete before it calls the `gti-execute-merge-malicious_urls` function.

1.  **Get the URL of the "Merge" function:**
    ```bash
    MERGE_FUNCTION_URL=$(gcloud functions describe $MERGE_FUNCTION_NAME --region=$GCP_REGION --gen2 --format='value(serviceConfig.uri)')
    ```
2.  **Create the scheduler job:**
    ```bash
    gcloud scheduler jobs create http $MERGE_SCHEDULER_NAME \
      --location=$GCP_REGION \
      --schedule="15 * * * *" \
      --uri=$MERGE_FUNCTION_URL \
      --http-method=POST \
      --oidc-service-account-email=$SCHEDULER_SA_EMAIL
    ```

---

## Key Challenges & Troubleshooting Guide

This pipeline is robust, but its deployment involves interactions between many different services. Several common issues were encountered and solved during its development. This guide documents them to aid in future troubleshooting.

### 5.1: Initial Approach: BigQuery Transfer Service

The initial architecture attempted to use the built-in BigQuery Data Transfer Service to load files from GCS. This approach was abandoned for two reasons:
* **Immutable Parameters**: Core settings like the GCS path (`data_path_template`) are immutable. If you need to change the path (e.g., from `/*` to `/**`), you must delete and recreate the entire transfer job.
* **Service Account Provisioning Failure**: In this project, the Transfer Service's required Google-managed service account failed to be created automatically. This is a rare backend issue but completely blocks the service from working. I could never get it to work, hence I abandoned it. 

**Solution**: The final architecture is more reliable as it replaces the Transfer Service with a dedicated, event-driven Cloud Function (`gti-load-data-malicious_urls`) that we have full control over.

### 5.2: Google-Managed Service Account Issues

A recurring theme was the failure of Google-managed service accounts (like for Cloud Scheduler) to be automatically provisioned, even for a Project Owner.

* **Problem**: When trying to grant IAM roles, I received `Service account ... does not exist` errors.
* **Standard Workaround**: I tried to find a workaround by creating a "dummy" resource (like a temporary scheduler job) to force the service to initialize itself and create its service account.
* **Solution**: When even the workaround failed, I (with gemini pro 2.5 now because I got stuck) pivoted to a more robust architecture that did not rely on these Google-managed accounts for authentication. Created a `gti-scheduler-invoker` service account and used it with OIDC tokens to call the required functions.

### 5.3: Authentication Errors (401/403: Not Authenticated)

When calling private Cloud Functions from Cloud Scheduler, we encountered `The request was not authenticated` errors.

* **Cause**: This is a two-part security requirement. It's not enough for the scheduler to send an authenticated request; the target function must also recognize the caller as being on its "guest list."
* **Solution**:
    1.  The Cloud Scheduler job must be configured with an **OIDC token** that points to a specific service account (our `gti-scheduler-invoker`).
    2.  That same service account (`gti-scheduler-invoker`) must be granted the **Invoker** role (`roles/run.invoker`) on the function it's trying to call.
    3.  The target **URI** in the scheduler job must exactly match the function's URI, without any trailing slashes (`/`).

### 5.4: BigQuery Load & `MERGE` Errors

* **Problem 1: `NULL` Values in Table**: The first successful loads inserted rows with all `NULL` values.
    * **Cause**: A mismatch between the field names in the source JSON file (`id`, `type`, `attributes`, etc.) and the column names in the BigQuery table (`ioc_id`, `ioc_type`, etc.).
    * **Solution**: The `gti-fetch-iocs-malicious_urls` function was updated to meticulously reshape the JSON, renaming and flattening keys to perfectly match the table schema before saving the file.

* **Problem 2: `MERGE must match at most one source row`**: The `MERGE` job failed during testing.
    * **Cause**: The staging table contained duplicate `ioc_id`s from multiple test runs. A `MERGE` statement requires that the source has only one match for each target row.
    * **Solution**: The `gti-load-data` function is configured with `WRITE_TRUNCATE`. This overwrites the staging table on every run, ensuring it only ever contains the latest batch of data and preventing this error in production.


---

## Usage / Testing

### Testing the Pipeline Logic

The repository includes unit tests to verify critical data transformation logic locally before deployment.

#### Testing the "Fetch" De-duplication Logic
This test simulates a "dirty" API response with duplicate records and verifies that only the most recent version of each record is kept.

1.  Navigate into the fetch function's directory:
    ```bash
    cd gti-fetch-iocs
    ```
2.  Run the test script:
    ```bash
    python3 test_fetch_dedup_logic.py
    ```

#### Testing the "Merge" SQL Generation
This test confirms that the `MERGE` SQL statement is constructed correctly inside the merge function, without needing to connect to BigQuery.

1.  Navigate into the merge function's directory:
    ```bash
    cd gti-execute-merge
    ```
2.  Install local dependencies if you haven't already:
    ```bash
    pip3 install google-cloud-bigquery
    ```
3.  Run the test script:
    ```bash
    python3 -m unittest test_merge_logic.py
    ```

### Manually Triggering the Pipeline
To run the entire pipeline immediately for testing purposes, you can manually trigger the first scheduler job. This will start the fetch, load, and merge sequence.

```bash
gcloud scheduler jobs run $FETCH_SCHEDULER_NAME --location=$GCP_REGION
```

### Querying the Final Data

To access the de-duplicated threat intelligence data, query the final table in BigQuery.

```bash
bq query --use_legacy_sql=false 'SELECT ioc_id, url, positives, last_analysis_date FROM `vt-data-lake.gti_threatintel_bq.malicious_urls` ORDER BY last_analysis_date DESC LIMIT 20'
```

## Cleanup

To avoid ongoing costs, run the following commands to delete all the resources created by this guide.

```bash
# Delete the Cloud Scheduler jobs
gcloud scheduler jobs delete $FETCH_SCHEDULER_NAME --location=$GCP_REGION --quiet
gcloud scheduler jobs delete $MERGE_SCHEDULER_NAME --location=$GCP_REGION --quiet

# Delete the Cloud Functions
gcloud functions delete $FETCH_FUNCTION_NAME --region=$GCP_REGION --gen2 --quiet
gcloud functions delete $LOAD_FUNCTION_NAME --region=$GCP_REGION --gen2 --quiet
gcloud functions delete $MERGE_FUNCTION_NAME --region=$GCP_REGION --gen2 --quiet

# Delete the GCS bucket and all its contents
gcloud storage rm --recursive gs://${BUCKET_NAME}

# Delete the BigQuery dataset and both tables
bq rm -r -f --dataset $GCP_PROJECT_ID:$BQ_DATASET_NAME

# Delete the secret from Secret Manager
gcloud secrets delete $SECRET_NAME --quiet

# Delete the service accounts
gcloud iam service-accounts delete $SERVICE_ACCOUNT_EMAIL --quiet
gcloud iam service-accounts delete $SCHEDULER_SA_EMAIL --quiet
```