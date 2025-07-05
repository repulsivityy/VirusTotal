# Use this for your merge function's main.py
import os
from google.cloud import bigquery

def execute_bigquery_merge(request):
    try:
        project_id = os.environ.get("GCP_PROJECT")
        dataset_name = os.environ.get("BQ_DATASET_NAME")
        table_name = os.environ.get("BQ_TABLE_NAME")
        staging_table_name = os.environ.get("BQ_STAGING_TABLE_NAME")
    except Exception as e:
        print(f"Error reading environment variables: {e}")
        return ("Internal Server Error: Missing environment variables.", 500)

    client = bigquery.Client()

    merge_query = f"""
        MERGE `{project_id}.{dataset_name}.{table_name}` T
        USING (
          SELECT * FROM `{project_id}.{dataset_name}.{staging_table_name}`
          QUALIFY ROW_NUMBER() OVER(PARTITION BY id ORDER BY attributes.last_analysis_date DESC) = 1
        ) S
        ON T.id = S.id

        WHEN MATCHED THEN
          UPDATE SET
            T.attributes = S.attributes,
            T.relationships = S.relationships

        WHEN NOT MATCHED THEN
          INSERT (id, attributes, relationships, ingestion_timestamp)
          VALUES (S.id, S.attributes, S.relationships, CURRENT_TIMESTAMP())
    """
    
    truncate_query = f"TRUNCATE TABLE `{project_id}.{dataset_name}.{staging_table_name}`"

    try:
        print(f"Executing MERGE from {staging_table_name} into {table_name}")
        merge_job = client.query(merge_query)
        merge_job.result()
        stats = merge_job.dml_stats
        print(f"Merge successful. Rows affected: inserted={stats.inserted_row_count}, updated={stats.updated_row_count}")

        print(f"Truncating staging table: {staging_table_name}")
        truncate_job = client.query(truncate_query)
        truncate_job.result()
        print("Staging table truncated successfully.")

        return ("Merge and truncate process completed successfully.", 200)

    except Exception as e:
        print(f"An error occurred during the merge/truncate process: {e}")
        return (f"An error occurred during the merge/truncate process: {e}", 500)