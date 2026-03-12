import os
import json
import logging
from google.cloud import bigquery

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def gcs_to_bigquery_loader(event, context):
    """
    Cloud Function triggered by GCS file creation to load into BQ staging table.
    """
    file_name = event['name']
    bucket_name = event['bucket']

    # Environment variables
    project_id = os.environ.get("GCP_PROJECT")
    dataset_name = os.environ.get("BQ_DATASET_NAME")
    table_name = os.environ.get("BQ_STAGING_TABLE_NAME") 
    schema_file = os.environ.get("SCHEMA_FILE_PATH", "schema_hashfeeds.json")

    uri = f"gs://{bucket_name}/{file_name}"
    logger.info(f"Processing GCS event: {uri} into staging table: {table_name}")

    client = bigquery.Client()
    dataset_ref = client.dataset(dataset_name, project=project_id)
    table_ref = dataset_ref.table(table_name)

    job_config = bigquery.LoadJobConfig()
    job_config.source_format = bigquery.SourceFormat.NEWLINE_DELIMITED_JSON
    # Use WRITE_APPEND to allow multiple files to be collected between merge runs
    job_config.write_disposition = bigquery.WriteDisposition.WRITE_APPEND
    job_config.ignore_unknown_values = True
    
    # Load explicit schema if provided
    if os.path.exists(schema_file):
        try:
            with open(schema_file, 'r') as f:
                schema_json = json.load(f)
                job_config.schema = [bigquery.SchemaField.from_api_repr(field) for field in schema_json]
                logger.info(f"Loaded explicit schema from {schema_file}")
        except Exception as e:
            logger.error(f"Failed to load schema from {schema_file}: {e}. Falling back to auto-detection.")
            job_config.autodetect = True
    else:
        logger.warning(f"Schema file {schema_file} not found. Falling back to auto-detection.")
        job_config.autodetect = True

    try:
        load_job = client.load_table_from_uri(
            uri,
            table_ref,
            job_config=job_config,
        )
        logger.info(f"Starting load job {load_job.job_id}")
        load_job.result() # Wait for job completion
        logger.info(f"Job finished. Successfully loaded {load_job.output_rows} rows.")

    except Exception as e:
        logger.error(f"Error loading data into BigQuery from {uri}: {e}")
        # Re-raise to trigger Cloud Function retry if enabled
        raise
