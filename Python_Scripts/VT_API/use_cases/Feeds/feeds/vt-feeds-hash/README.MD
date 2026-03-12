# VirusTotal File Hash Feeds - Optimized Threat Intelligence Pipeline

This pipeline is an optimized version of the domain feeds pipeline, specifically tailored for VirusTotal / Google Threat Intelligence **File Hash** feeds.

## Optimizations & Improvements

Compared to the original `vt-feeds-domain` pipeline, this version introduces the following enhancements:

### 1. Enhanced API Resilience & Performance (`vt-fetch-hash`)
- **Parallel Fetching:** Instead of sequential processing, it uses `ThreadPoolExecutor` to fetch and stream multiple minutes of data in parallel, significantly reducing the total execution time of the 10-minute batch window.
- **Robust Networking:** Implements `requests.Session` with a `Retry` strategy (handling 429, 500, 502, 503, 504 errors) to deal with transient network issues or API rate limiting.
- **Optimized Stream Buffers:** Increased chunk sizes for GCS streaming to improve throughput for large file hash feeds.

### 2. Structured Configuration & Observability
- **Centralized Settings:** Both fetch and merge functions use a dedicated `Config`/`Settings` class for environment variable management, ensuring all required parameters are present before execution.
- **Professional Logging:** Replaced `print` statements with the Python `logging` module. This provides structured logs that integrate seamlessly with Google Cloud Logging, allowing for better monitoring, alerting, and debugging.

### 3. Data Integrity & Schema Management (`vt-load-hash`)
- **Explicit Schema Enforcement:** Unlike the domain loader, this hash loader uses an explicit `schema_hashfeeds.json` file. This prevents schema inference errors and ensures that complex nested structures (like `last_analysis_stats` or `gti_assessment`) are correctly mapped in BigQuery.
- **Improved Staging Logic:** Maintains the `WRITE_APPEND` strategy to collect all minute-level files between merge cycles, with the merge function handling final deduplication.

### 4. Optimized Data Merging (`vt-execute-merge-hash`)
- **DML Stats Reporting:** The merge function now reports detailed statistics (rows inserted/updated) to Cloud Logging, providing clear visibility into each merge cycle's impact.
- **Modular Query Construction:** The MERGE query is constructed dynamically using configuration parameters, making the code cleaner and easier to maintain.

## Architecture Overview
The pipeline follows the same event-driven model:

1.  **Cloud Scheduler (Fetch):** Triggers `vt-fetch-hash` every 10 minutes.
2.  **Cloud Function (Fetch Hash):** Fetches the last 10 minutes of file hash feeds (offset by 1 hour) and streams them to GCS.
3.  **Cloud Storage Bucket:** Landing zone for raw NDJSON files.
4.  **Cloud Function (Load to Staging):** Triggered by GCS, loads data into BigQuery staging using the explicit schema.
5.  **Cloud Scheduler (Merge):** Triggers `vt-execute-merge-hash` every 30 minutes.
6.  **Cloud Function (Execute Merge):** De-duplicates the staging table on-the-fly and merges into the production table.
7.  **BigQuery:** Final destination for the file hash intelligence.

## Deployment Notes
Refer to the original `README.MD` for general deployment instructions. Ensure the following environment variables are updated for the hash feed:
- `THREAT_LIST`: "vt-file-feed"
- `FEED_TYPE`: "files"
- `SCHEMA_FILE_PATH`: "schema_hashfeeds.json"
- `ENTRY_POINT` for fetch: `fetch_and_stream_hash_feed`
- `ENTRY_POINT` for merge: `execute_bigquery_merge_hash`
