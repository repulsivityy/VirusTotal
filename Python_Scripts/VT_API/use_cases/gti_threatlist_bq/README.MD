# GTI Threat Intelligence Pipeline

This project creates a serverless, automated data pipeline on Google Cloud. 

Workflow: 
1. It fetches a list of categorised threats hourly from the Google Threat Intelligence's Categorised Threat List via API. 
2. Ingests the data into Google BigQuery, and maintains a de-duplicated, up-to-date dataset by merging new data with existing records. 
3. The entire process is event-driven and designed for reliability and low operational overhead.

Change logs are handled by github version control. I suck at writing good commit messages, and this forces me to build a good habit of commiting often. 
---

### Pipeline #1 - Malicious Network Infrastructure, URLS

I started with the `malicious_network_infra_url` first. My main focus was to collect all the URLs into BQ for analysis. Follow the README there to set up the pipeline. 

### Pipeline #2 - Infostealers, Files

Decided to continue the pipeline with Infostealers, since Infostealers are on the rise. Followed pipeline 1's guide, but still encountered errors. This is highlighted in section 5. My learnings have been back-ported to Pipeline 1, and it's reflected in the README. 

