import os
from google.cloud import bigquery

def gcs_to_bigquery_loader(event, context):
    """
    Cloud Function that triggers on GCS file creation and loads it into a BQ staging table.
    """
    file_name = event['name']
    bucket_name = event['bucket']

    project_id = os.environ.get("GCP_PROJECT")
    dataset_name = os.environ.get("BQ_DATASET_NAME")
    # Update to match the new staging table name
    table_name = os.environ.get("BQ_STAGING_TABLE_NAME") 

    uri = f"gs://{bucket_name}/{file_name}"
    print(f"Processing file: {uri} into staging table: {table_name}")

    client = bigquery.Client()
    dataset_ref = client.dataset(dataset_name, project=project_id)
    table_ref = dataset_ref.table(table_name)

    job_config = bigquery.LoadJobConfig()
    job_config.source_format = bigquery.SourceFormat.NEWLINE_DELIMITED_JSON
    # Overwrite the staging table with the new data each time
    #job_config.write_disposition = bigquery.WriteDisposition.WRITE_TRUNCATE 
    job_config.write_disposition = bigquery.WriteDisposition.WRITE_APPEND #specifically write append to staging table, and merge function will handle the deduplication and merge. 
    job_config.ignore_unknown_values = True

    try:
        load_job = client.load_table_from_uri(
            uri,
            table_ref,
            job_config=job_config,
        )
        print(f"Starting job {load_job.job_id}")
        load_job.result()
        print("Job finished.")

    except Exception as e:
        print(f"Error loading data into BigQuery: {e}")
        raise