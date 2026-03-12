import os
import logging
from google.cloud import bigquery

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class Config:
    """Centralized environment variables management."""
    def __init__(self):
        self.project_id = os.environ.get("GCP_PROJECT")
        self.dataset_name = os.environ.get("BQ_DATASET_NAME")
        self.table_name = os.environ.get("BQ_TABLE_NAME")
        self.staging_table_name = os.environ.get("BQ_STAGING_TABLE_NAME")
        
        if not all([self.project_id, self.dataset_name, self.table_name, self.staging_table_name]):
            raise ValueError("Missing essential environment variables: GCP_PROJECT, BQ_DATASET_NAME, BQ_TABLE_NAME, BQ_STAGING_TABLE_NAME")

def build_merge_query(config):
    """Builds the BigQuery MERGE query."""
    return f"""
        MERGE `{config.project_id}.{config.dataset_name}.{config.table_name}` T
        USING (
          SELECT * FROM `{config.project_id}.{config.dataset_name}.{config.staging_table_name}`
          -- Deduplicate source data based on id and latest analysis date
          QUALIFY ROW_NUMBER() OVER(PARTITION BY id ORDER BY attributes.last_analysis_date DESC) = 1
        ) S
        ON T.id = S.id

        WHEN MATCHED THEN
          UPDATE SET
            T.attributes = S.attributes,
            T.relationships = S.relationships,
            T.context_attributes = S.context_attributes

        WHEN NOT MATCHED THEN
          INSERT (id, context_attributes, attributes, relationships, ingestion_timestamp)
          VALUES (S.id, S.context_attributes, S.attributes, S.relationships, CURRENT_TIMESTAMP())
    """

def execute_bigquery_merge_hash(request):
    """Main entry point for Cloud Function."""
    try:
        config = Config()
    except Exception as e:
        logger.critical(f"Initialization failed: {e}")
        return ("Internal Server Error", 500)

    client = bigquery.Client()

    merge_query = build_merge_query(config)
    truncate_query = f"TRUNCATE TABLE `{config.project_id}.{config.dataset_name}.{config.staging_table_name}`"

    try:
        logger.info(f"Executing MERGE from {config.staging_table_name} into {config.table_name}")
        merge_job = client.query(merge_query)
        merge_job.result() # Wait for completion
        
        stats = merge_job.dml_stats
        logger.info(f"Merge successful. Rows inserted: {stats.inserted_row_count}, updated: {stats.updated_row_count}")

        logger.info(f"Truncating staging table: {config.staging_table_name}")
        truncate_job = client.query(truncate_query)
        truncate_job.result()
        logger.info("Staging table truncated successfully.")

        return ("Merge and truncate process completed successfully.", 200)

    except Exception as e:
        logger.error(f"An error occurred during the merge/truncate process: {e}")
        return (f"An error occurred during the merge/truncate process: {e}", 500)
