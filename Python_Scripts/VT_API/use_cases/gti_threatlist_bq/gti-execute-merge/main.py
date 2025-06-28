import os
from google.cloud import bigquery

def execute_bigquery_merge(request):
    """
    Cloud Function that triggers via HTTP to execute a robust BigQuery MERGE statement.
    """
    project_id = os.environ.get("GCP_PROJECT")
    dataset_name = os.environ.get("BQ_DATASET_NAME")
    
    # This MERGE statement uses COALESCE to only update target fields if the
    # new value from the staging table (S) is not NULL. Otherwise, it keeps
    # the existing value from the target table (T).
    sql_query = f"""
        MERGE `{project_id}.{dataset_name}.malicious_urls` T
        USING `{project_id}.{dataset_name}.malicious_urls_staging` S
        ON T.ioc_id = S.ioc_id
        WHEN MATCHED THEN
          UPDATE SET
            T.ioc_type = COALESCE(S.ioc_type, T.ioc_type),
            T.url = COALESCE(S.url, T.url),
            T.tld = COALESCE(S.tld, T.tld),
            T.positives = COALESCE(S.positives, T.positives),
            T.times_submitted = COALESCE(S.times_submitted, T.times_submitted),
            T.first_submission_date = COALESCE(S.first_submission_date, T.first_submission_date),
            T.last_submission_date = COALESCE(S.last_submission_date, T.last_submission_date),
            T.last_analysis_date = COALESCE(S.last_analysis_date, T.last_analysis_date),
            T.last_modification_date = COALESCE(S.last_modification_date, T.last_modification_date),
            T.last_analysis_stats_harmless = COALESCE(S.last_analysis_stats_harmless, T.last_analysis_stats_harmless),
            T.last_analysis_stats_malicious = COALESCE(S.last_analysis_stats_malicious, T.last_analysis_stats_malicious),
            T.last_analysis_stats_suspicious = COALESCE(S.last_analysis_stats_suspicious, T.last_analysis_stats_suspicious),
            T.last_analysis_stats_undetected = COALESCE(S.last_analysis_stats_undetected, T.last_analysis_stats_undetected),
            T.gti_assessment_severity = COALESCE(S.gti_assessment_severity, T.gti_assessment_severity),
            T.gti_assessment_threat_score = COALESCE(S.gti_assessment_threat_score, T.gti_assessment_threat_score),
            T.gti_assessment_verdict = COALESCE(S.gti_assessment_verdict, T.gti_assessment_verdict),
            T.categories = COALESCE(S.categories, T.categories),
            T.relationships = COALESCE(S.relationships, T.relationships)
        WHEN NOT MATCHED BY SOURCE THEN
            DELETE
        WHEN NOT MATCHED THEN
          INSERT ROW;
    """
    
    print("Executing MERGE statement...")
    
    client = bigquery.Client()
    
    try:
        query_job = client.query(sql_query)
        query_job.result() # Waits for the job to complete
        print("Successfully executed merge query.")
        return ("Successfully executed merge query.", 200)
    except Exception as e:
        print(f"Error executing merge query: {e}")
        return ("Error executing merge query.", 500)