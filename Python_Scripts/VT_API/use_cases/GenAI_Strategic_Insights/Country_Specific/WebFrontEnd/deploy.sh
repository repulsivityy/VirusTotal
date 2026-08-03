#!/bin/bash

# Configuration
SERVICE_NAME="country-specific-gti"
REGION="asia-southeast1"

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ gcloud CLI is not installed. Please install it first."
    exit 1
fi

# Check if user is authenticated
echo "🔍 Checking gcloud authentication..."
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
    echo "⚠️  You are not authenticated. Please run 'gcloud auth login' first."
    exit 1
fi

# Get current project
PROJECT_ID=$(gcloud config get-value project)
if [ -z "$PROJECT_ID" ]; then
    echo "⚠️  No project selected. Please run 'gcloud config set project <PROJECT_ID>'."
    exit 1
fi

echo "🔌 Enabling Secret Manager API..."
gcloud services enable secretmanager.googleapis.com --project="$PROJECT_ID"

# Load local .env if present to populate env vars if not already exported
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs 2>/dev/null)
fi

# Helper function to create or update secrets in Secret Manager
create_or_update_secret() {
    local SECRET_NAME=$1
    local SECRET_VALUE=$2
    local ENV_VAR_NAME=$3

    if gcloud secrets describe "$SECRET_NAME" --project="$PROJECT_ID" &>/dev/null; then
        if [ -n "$SECRET_VALUE" ]; then
            echo "🔑 Updating secret '$SECRET_NAME'..."
            echo -n "$SECRET_VALUE" | gcloud secrets versions add "$SECRET_NAME" --data-file=- --project="$PROJECT_ID" >/dev/null
        else
            echo "ℹ️  Secret '$SECRET_NAME' already exists in Secret Manager."
        fi
    else
        if [ -z "$SECRET_VALUE" ]; then
            echo "❌ Secret '$SECRET_NAME' does not exist in Secret Manager and environment variable $ENV_VAR_NAME is not set."
            exit 1
        fi
        echo "🔑 Creating secret '$SECRET_NAME'..."
        gcloud secrets create "$SECRET_NAME" --replication-policy="automatic" --project="$PROJECT_ID" >/dev/null
        echo -n "$SECRET_VALUE" | gcloud secrets versions add "$SECRET_NAME" --data-file=- --project="$PROJECT_ID" >/dev/null
    fi
}

echo "🔐 Setting up Secret Manager secrets..."
create_or_update_secret "country_landscape_gemini_key" "$GEMINI_APIKEY" "GEMINI_APIKEY"
create_or_update_secret "country_landscape_gti_key" "$GTI_APIKEY" "GTI_APIKEY"

# Ensure default Compute service account has Secret Accessor role
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

echo "🛡️  Granting Secret Accessor permission to default Compute service account..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$COMPUTE_SA" \
    --role="roles/secretmanager.secretAccessor" \
    --condition=None >/dev/null 2>&1

echo "🚀 Deploying to Cloud Run..."
echo "--------------------------------"
echo "Project: $PROJECT_ID"
echo "Service: $SERVICE_NAME"
echo "Region:  $REGION"
echo "--------------------------------"

# confirm
read -p "Do you want to proceed? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --port 8080 \
  --set-secrets="GEMINI_APIKEY=country_landscape_gemini_key:latest,GTI_APIKEY=country_landscape_gti_key:latest"

if [ $? -eq 0 ]; then
    echo "✅ Deployment successful!"
else
    echo "❌ Deployment failed."
    exit 1
fi
