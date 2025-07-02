import os
from google.cloud import bigquery

def execute_bigquery_merge(request):
    """
    Cloud Function that triggers via HTTP to merge the infostealer staging table
    into the final production table.
    """
    try:
        project_id = os.environ.get("GCP_PROJECT")
        dataset_name = os.environ.get("BQ_DATASET_NAME")
        # These will be set by the deployment command to 'infostealer' and 'infostealer_staging'
        table_name = os.environ.get("BQ_TABLE_NAME")
        staging_table_name = os.environ.get("BQ_STAGING_TABLE_NAME")
    except Exception as e:
        print(f"Error reading environment variables: {e}")
        return ("Internal Server Error: Missing environment variables.", 500)

    # This MERGE statement uses COALESCE to only update target fields if the
    # new value from the staging table (S) is not NULL. Otherwise, it keeps
    # the existing value from the target table (T).
    sql_query = f"""
        MERGE `{project_id}.{dataset_name}.{table_name}` T
        USING `{project_id}.{dataset_name}.{staging_table_name}` S
        ON T.ioc_id = S.ioc_id
        WHEN MATCHED THEN
          UPDATE SET
            T.ioc_type = COALESCE(S.ioc_type, T.ioc_type),
            T.md5 = COALESCE(S.md5, T.md5),
            T.vhash = COALESCE(S.vhash, T.vhash),
            T.meaningful_name = COALESCE(S.meaningful_name, T.meaningful_name),
            T.names = COALESCE(S.names, T.names),
            T.type_tags = COALESCE(S.type_tags, T.type_tags),
            T.positives = COALESCE(S.positives, T.positives),
            T.times_submitted = COALESCE(S.times_submitted, T.times_submitted),
            T.creation_date = COALESCE(S.creation_date, T.creation_date),
            T.first_submission_date = COALESCE(S.first_submission_date, T.first_submission_date),
            T.last_submission_date = COALESCE(S.last_submission_date, T.last_submission_date),
            T.last_analysis_date = COALESCE(S.last_analysis_date, T.last_analysis_date),
            T.last_modification_date = COALESCE(S.last_modification_date, T.last_modification_date),
            T.last_analysis_stats_harmless = COALESCE(S.last_analysis_stats_harmless, T.last_analysis_stats_harmless),
            T.last_analysis_stats_malicious = COALESCE(S.last_analysis_stats_malicious, T.last_analysis_stats_malicious),
            T.last_analysis_stats_suspicious = COALESCE(S.last_analysis_stats_suspicious, T.last_analysis_stats_suspicious),
            T.last_analysis_stats_undetected = COALESCE(S.last_analysis_stats_undetected, T.last_analysis_stats_undetected),
            T.last_analysis_stats_timeout = COALESCE(S.last_analysis_stats_timeout, T.last_analysis_stats_timeout),
            T.last_analysis_stats_typeUnsupported = COALESCE(S.last_analysis_stats_typeUnsupported, T.last_analysis_stats_typeUnsupported),
            T.gti_assessment_severity = COALESCE(S.gti_assessment_severity, T.gti_assessment_severity),
            T.gti_assessment_threat_score = COALESCE(S.gti_assessment_threat_score, T.gti_assessment_threat_score),
            T.gti_assessment_verdict = COALESCE(S.gti_assessment_verdict, T.gti_assessment_verdict),
            T.relationships = COALESCE(S.relationships, T.relationships)
        WHEN NOT MATCHED THEN
          INSERT ROW;
    """
    
    print(f"Executing MERGE into table: {table_name}")
    
    client = bigquery.Client()
    
    try:
        query_job = client.query(sql_query)
        query_job.result() # Waits for the job to complete
        print("Successfully executed merge query.")
        return ("Successfully executed merge query.", 200)
    except Exception as e:
        print(f"Error executing merge query: {e}")
        return (f"Error executing merge query: {e}", 500)