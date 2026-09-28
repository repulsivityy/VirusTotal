#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Configuration
SERVICE_NAME="vul-intel-dashboard"
REGION="asia-southeast1"

# Fetch active gcloud project if not explicitly set
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)

if [ -z "$PROJECT_ID" ]; then
  echo "Error: No active gcloud project found. Please log in or configure a project: gcloud config set project <PROJECT_ID>"
  exit 1
fi

echo "Deploying to project: $PROJECT_ID"
echo "Service name: $SERVICE_NAME"
echo "Region: $REGION"
echo "----------------------------------------"



# Fetch keys from local .env if present
GTI_KEY_SECRET_NAME="vul-intel-gti-key"
GEMINI_KEY_SECRET_NAME="vul-intel-gemini-key"

PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")
COMPUTE_SVC_ACCT="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

setup_secret() {
  local secret_name=$1
  local secret_value=$2

  if [ -z "$secret_value" ]; then
    echo "Warning: No value provided for secret $secret_name. Skipping secret creation."
    return 1
  fi

  # Check if secret exists
  if ! gcloud secrets describe "$secret_name" >/dev/null 2>&1; then
    echo "Creating secret $secret_name in Secret Manager..."
    gcloud secrets create "$secret_name" --replication-policy="automatic"
  else
    echo "Secret $secret_name already exists."
  fi

  # Add secret version
  echo "Uploading new version for secret $secret_name..."
  echo -n "$secret_value" | gcloud secrets versions add "$secret_name" --data-file=-

  # Grant Access to Cloud Run Default Service Account
  echo "Granting Secret Accessor role to $COMPUTE_SVC_ACCT on $secret_name..."
  gcloud secrets add-iam-policy-binding "$secret_name" \
    --member="serviceAccount:$COMPUTE_SVC_ACCT" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet
}

# Read variables from .env file
HAS_GTI_SECRET=false
HAS_GEMINI_SECRET=false

GTI_KEY_VAL=""
GEMINI_KEY_VAL=""

if [ -f .env ]; then
  echo "Reading API keys from .env file..."
  GTI_KEY_VAL=$(grep -E "^GTI_API_KEY=" .env | cut -d'=' -f2- | tr -d '"' | tr -d "'" | xargs || true)
  GEMINI_KEY_VAL=$(grep -E "^GEMINI_API_KEY=" .env | cut -d'=' -f2- | tr -d '"' | tr -d "'" | xargs || true)
fi

# Check if secrets already exist in Secret Manager if not provided in .env
if [ -z "$GTI_KEY_VAL" ]; then
  if gcloud secrets describe "$GTI_KEY_SECRET_NAME" >/dev/null 2>&1; then
    HAS_GTI_SECRET=true
  fi
fi

if [ -z "$GEMINI_KEY_VAL" ]; then
  if gcloud secrets describe "$GEMINI_KEY_SECRET_NAME" >/dev/null 2>&1; then
    HAS_GEMINI_SECRET=true
  fi
fi

# Create/Update secrets in Secret Manager if new values are provided
if [ -n "$GTI_KEY_VAL" ]; then
  setup_secret "$GTI_KEY_SECRET_NAME" "$GTI_KEY_VAL"
  HAS_GTI_SECRET=true
fi

if [ -n "$GEMINI_KEY_VAL" ]; then
  setup_secret "$GEMINI_KEY_SECRET_NAME" "$GEMINI_KEY_VAL"
  HAS_GEMINI_SECRET=true
fi

# Build secret reference parameter for Cloud Run deploy
SECRET_PARAMS=""
if [ "$HAS_GTI_SECRET" = true ]; then
  SECRET_PARAMS="GTI_API_KEY=${GTI_KEY_SECRET_NAME}:latest"
fi
if [ "$HAS_GEMINI_SECRET" = true ]; then
  if [ -n "$SECRET_PARAMS" ]; then
    SECRET_PARAMS="${SECRET_PARAMS},GEMINI_API_KEY=${GEMINI_KEY_SECRET_NAME}:latest"
  else
    SECRET_PARAMS="GEMINI_API_KEY=${GEMINI_KEY_SECRET_NAME}:latest"
  fi
fi

# 1. Build the container image using Google Cloud Builds
echo "Building container image using Cloud Build..."
IMAGE_TAG="gcr.io/$PROJECT_ID/$SERVICE_NAME:latest"
gcloud builds submit --tag "$IMAGE_TAG"

# 2. Deploy to Google Cloud Run
echo "Deploying to Google Cloud Run..."
if [ -n "$SECRET_PARAMS" ]; then
  echo "Mounting Secret Manager secrets: $SECRET_PARAMS"
  gcloud run deploy "$SERVICE_NAME" \
    --image "$IMAGE_TAG" \
    --platform managed \
    --region "$REGION" \
    --allow-unauthenticated \
    --set-secrets="$SECRET_PARAMS"
else
  gcloud run deploy "$SERVICE_NAME" \
    --image "$IMAGE_TAG" \
    --platform managed \
    --region "$REGION" \
    --allow-unauthenticated
fi

echo "----------------------------------------"
echo "Deployment completed successfully!"
