import os
from google.cloud import bigquery

def execute_bigquery_merge(request):
    """
    Cloud Function that triggers via HTTP to execute a BigQuery MERGE statement.
    """
    project_id = os.environ.get("GCP_PROJECT")
    dataset_name = os.environ.get("BQ_DATASET_NAME")

    # The MERGE statement to run
    sql_query = f"""
        MERGE `{project_id}.{dataset_name}.malicious_urls` T
        USING `{project_id}.{dataset_name}.malicious_urls_staging` S
        ON T.ioc_id = S.ioc_id
        WHEN MATCHED THEN
          UPDATE SET
            ioc_type = S.ioc_type,
            url = S.url,
            tld = S.tld,
            positives = S.positives,
            times_submitted = S.times_submitted,
            first_submission_date = S.first_submission_date,
            last_submission_date = S.last_submission_date,
            last_analysis_date = S.last_analysis_date,
            last_modification_date = S.last_modification_date,
            last_analysis_stats_harmless = S.last_analysis_stats_harmless,
            last_analysis_stats_malicious = S.last_analysis_stats_malicious,
            last_analysis_stats_suspicious = S.last_analysis_stats_suspicious,
            last_analysis_stats_undetected = S.last_analysis_stats_undetected,
            gti_assessment_severity = S.gti_assessment_severity,
            gti_assessment_threat_score = S.gti_assessment_threat_score,
            gti_assessment_verdict = S.gti_assessment_verdict,
            categories = S.categories,
            relationships = S.relationships
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