# VirusTotal Domain Feeds - Threat Intelligence Pipeline
>again, got lazy and used gemini to generate the readme, so if it looks too profesh, that's why. 

This serverless, automated data pipeline runs on Google Cloud to build a comprehensive database of domain intelligence. It fetches domain feeds hourly from the Google Threat Intelligence (GTI) API, ingests the data into Google BigQuery, and maintains a de-duplicated, up-to-date dataset by intelligently merging new data with existing records.

The architecture is event-driven and designed for high reliability and low operational overhead, ensuring that even intermittently available data from the source API is captured correctly.

## Architecture Overview
The pipeline follows a proven event-driven model:

1. **Cloud Scheduler (Fetch):** A cron job (*/10 * * * *) triggers the pipeline every 10 minutes.
2. **Cloud Function (Fetch Domains):** Fetches the last 10 minutes of domain feeds from the GTI API, using a memory-efficient streaming process to upload the raw data directly to a Cloud Storage bucket.
3. **Cloud Storage Bucket:** A landing zone for the raw, newline-delimited JSON (NDJSON) files.
4. **Cloud Function (Load to Staging):** Triggered by new files in the bucket, this function appends the data into a BigQuery "staging" table.
5. **Cloud Scheduler (Merge):** A second cron job (5,35 * * * *) runs every 30 minutes to trigger the merge process.
6. **Cloud Function (Execute Merge):** This function runs a "smart" MERGE query that de-duplicates the staging table on the fly before updating the final production table. It then truncates the staging table.
7. **BigQuery:** Hosts the staging table and the final, de-duplicated domains table, ready for analysis and machine learning models.

## Key Challenges & Solutions
This project's success depended on overcoming several specific challenges related to data volume, availability, and structure.

#### 1. Challenge: Out-of-Memory Errors in Fetch Function
- **Problem:** The initial version of the fetch function attempted to download and decompress entire feed files in memory before uploading them. For large feeds, this caused the Cloud Function to exceed its memory allocation, resulting in Out of memory and SIGKILL errors.

- **Solution:** The function was re-architected to stream data directly from the source to the destination. The final implementation uses requests.get(stream=True) to download the feed in small chunks. Each chunk is decompressed on-the-fly and written directly to a GCS blob stream via blob.open("wb"). This approach maintains a very low and constant memory footprint, regardless of the feed file size, making the function highly reliable and efficient.

#### 2. Challenge: Intermittent Source Data and Potential Data Loss
- **Problem:** VirusTotal does not guarantee a feed file for every single minute. The initial design, which overwrote the staging table on each load (WRITE_TRUNCATE), created a critical flaw: if multiple files arrived between merge runs, only the contents of the last file would be preserved in the staging table, causing data from earlier files to be lost.

- **Solution:** We implemented a more robust, two-part solution:
    - Append to Staging: The load function's write disposition was changed from WRITE_TRUNCATE to WRITE_APPEND. This ensures all data from all incoming files is accumulated in the staging table.

    - "Smart" Merge Query: Appending data introduces duplicates into the staging table. We enhanced the MERGE query to de-duplicate the source data before merging. It now uses the QUALIFY ROW_NUMBER() window function to select only the most recent version of each domain, based on attributes.last_analysis_date. This guarantees data integrity and prevents duplicates in the final table.

```bash
MERGE `project.dataset.domains` T
USING (
  -- De-duplicate the source on-the-fly
  SELECT * FROM `project.dataset.staging_domains`
  QUALIFY ROW_NUMBER() OVER(PARTITION BY id ORDER BY attributes.last_analysis_date DESC) = 1
) S
ON T.id = S.id
WHEN MATCHED THEN ...
WHEN NOT MATCHED THEN ...
```