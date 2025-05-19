#####################################
GCP Cloud Bucket Sandbox Enrivonment
Note 1 - Code was optimised with Gemini 2.5 pro
Note 2 - GTI API Key is hardcoded into the code. Use secrets manager if needed. 
Note 3 - This uses GCloud Commmands.

TODO 1: Migrate to TF 
TODO 2: Integrate ClamAV Scanning from https://cloud.google.com/architecture/automate-malware-scanning-for-documents-uploaded-to-cloud-storage

Disclaimer - Use at your own risk
#####################################

#### Configuration
```
export PROJECT_ID="<ProjectID>"
export REGION="<Region>"
# DANGER: Hardcoding API key for testing ONLY. Do NOT commit this key.
export GTI_API_KEY="<GTI_APIKEY>"
```

#### Resource Names (modify if needed, must be unique)
```
export NEW_BUCKET_NAME="${PROJECT_ID}-gti-new-files"
export ALLOW_BUCKET_NAME="${PROJECT_ID}-gti-allow-files"
export QUARANTINE_BUCKET_NAME="${PROJECT_ID}-gti-quarantine-files"
export FUNCTION_SERVICE_ACCOUNT="gti-scanner-func-sa"
export FUNCTION_NAME="gti-file-scanner"
```

#### Derived variables
```
export FUNCTION_SA_EMAIL="${FUNCTION_SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com"
export PROJECT_NUMBER=$(gcloud projects describe ${PROJECT_ID} --format='value(projectNumber)') # Needed for IAM binding
```

#### Set gcloud defaults for convenience
```
gcloud config set project $PROJECT_ID
gcloud config set functions/region $REGION
gcloud config set eventarc/location $REGION 

echo "Using Project: ${PROJECT_ID}, Region: ${REGION}"
echo "Service Account: ${FUNCTION_SA_EMAIL}"
echo "Buckets: ${NEW_BUCKET_NAME}, ${ALLOW_BUCKET_NAME}, ${QUARANTINE_BUCKET_NAME}"
echo "Using GTI API Key ending in: ${GTI_API_KEY: -4}" # Verify without printing the whole key
```

#### Enable the relevant cloud APIs
```
gcloud services enable \
  cloudfunctions.googleapis.com \
  storage.googleapis.com \
  eventarc.googleapis.com \
  run.googleapis.com \
  logging.googleapis.com \
  cloudbuild.googleapis.com \
  iam.googleapis.com \
  secretmanager.googleapis.com # Keep enabled for easier switch later
```

#### Grant Pub/Sub permissions to service account
```
echo "Granting Pub/Sub Publisher role to the project's Cloud Storage service account."
export GCS_SERVICE_ACCOUNT="service-${PROJECT_NUMBER}@gs-project-accounts.iam.gserviceaccount.com"
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="serviceAccount:${GCS_SERVICE_ACCOUNT}" \
    --role="roles/pubsub.publisher" \
    --condition=None
echo "Pub/Sub Publisher role granted to ${GCS_SERVICE_ACCOUNT}."
```

#### Create the buckets
```
gcloud storage buckets create gs://${NEW_BUCKET_NAME} --location=${REGION}
gcloud storage buckets create gs://${ALLOW_BUCKET_NAME} --location=${REGION}
gcloud storage buckets create gs://${QUARANTINE_BUCKET_NAME} --location=${REGION}
echo "Created buckets."
```

#### Create Service Account
```
gcloud iam service-accounts create ${FUNCTION_SERVICE_ACCOUNT} \
  --display-name="GTI Scanner Function Service Account"
echo "Created service account ${FUNCTION_SA_EMAIL}."
```

#### Granting Permissions to Service Account
```
# Permission for Cloud Storage access
gcloud storage buckets add-iam-policy-binding gs://${NEW_BUCKET_NAME} \
  --member="serviceAccount:${FUNCTION_SA_EMAIL}" \
  --role="roles/storage.objectUser" # Read/Write/Delete in source

gcloud storage buckets add-iam-policy-binding gs://${ALLOW_BUCKET_NAME} \
  --member="serviceAccount:${FUNCTION_SA_EMAIL}" \
  --role="roles/storage.objectCreator" # Create in destination

gcloud storage buckets add-iam-policy-binding gs://${QUARANTINE_BUCKET_NAME} \
  --member="serviceAccount:${FUNCTION_SA_EMAIL}" \
  --role="roles/storage.objectCreator" # Create in destination

# Permission to be invoked by Eventarc
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --member="serviceAccount:${FUNCTION_SA_EMAIL}" \
  --role="roles/eventarc.eventReceiver"

# Permission for Eventarc to use the service account
gcloud iam service-accounts add-iam-policy-binding ${FUNCTION_SA_EMAIL} \
   --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-eventarc.iam.gserviceaccount.com" \
   --role="roles/iam.serviceAccountUser" \
   --project=${PROJECT_ID}
echo "Granted IAM permissions to service account."
```

#### Deploying the Cloud Function
Run this on your terminal that has the python file 
```
gcloud functions deploy ${FUNCTION_NAME} \
  --gen2 \
  --runtime=python311 \
  --entry-point=scan_file_gti \
  --source=. \
  --service-account=${FUNCTION_SA_EMAIL} \
  --trigger-event-filters="type=google.cloud.storage.object.v1.finalized" \
  --trigger-event-filters="bucket=${NEW_BUCKET_NAME}" \
  --set-env-vars="GCP_PROJECT=${PROJECT_ID},ALLOW_BUCKET=${ALLOW_BUCKET_NAME},QUARANTINE_BUCKET=${QUARANTINE_BUCKET_NAME},GTI_API_KEY=${GTI_API_KEY},GTI_DISABLE_SANDBOX=true,GTI_INTERCEPT_TLS=true,GTI_RETENTION_DAYS=1,GTI_STORAGE_REGION=US,GTI_LOCALE=EN_US,GTI_ENABLE_INTERNET=true,POLL_INTERVAL_SECONDS=15,GTI_TOOL_NAME=gti_scanner" \
  --timeout=540s \
  --allow-unauthenticated #allow-unauthenticated for testing
```
