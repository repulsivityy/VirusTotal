# AVER: ASM Vulnerability Enrichment & Reporting Tool

## Overview

The **ASM Vulnerability Enrichment Tool** (`asmExportReport.py`) is a comprehensive utility designed to bridge the gap between Attack Surface Management (ASM) findings and actionable threat intelligence.

It automates the process of exporting asset and issue data from **Google Threat Intelligence (GTI)** or **Mandiant Advantage ASM**, enriches vulnerability findings with deep context from **Mandiant Intelligence (MATI)**, and generates interactive HTML reports for prioritization.

## Key Features

  * **Multi-Platform Support**: Works with both Google Threat Intelligence and Mandiant Advantage ASM.
  * **Automated Data Export**: Asynchronously fetch Entities, Technologies, and Issues from selected ASM projects and collections.
  * **Deep Vulnerability Enrichment**: Automatically extracts CVEs from ASM issues and enriches them with Mandiant Intelligence data, including:
      * Risk & Exploit Ratings
      * CVSS Scores (v3.1/v3.0)
      * Exploitation status (e.g., "Available", "Confirmed", "High")
  * **Interactive Reporting**: Generates a self-contained HTML report with visualization dashboards and detailed vulnerability tables.
  * **Cloud Integration**: Optional integrated support for uploading all report artifacts directly to a Google Cloud Storage (GCS) bucket.

## Prerequisites

### Python Dependencies

The script requires Python 3 and several external libraries. Install them using pip:

```bash
pip install requests pandas jinja2 tqdm aiohttp
```

*Optional (for GCP upload features):*

```bash
pip install google-cloud-storage
```

### API Credentials

This tool requires access to multiple API services. It will prompt you to enter these on the first run and save them securely in your home directory under `.api-credentials/`.

| Service | Required For | Credential File |
| :--- | :--- | :--- |
| **Google Threat Intel** | ASM Data Export (Default Mode) | `googleti-api-credentials.json` |
| **Mandiant Advantage** | ASM Data Export (`-adv` mode) | `adv-asm-api-credentials.json` |
| **Mandiant Intel (MATI)**| CVE Enrichment & Reporting | `mati-api-credentials.json` |

### Template Files

Ensure the following directory structure exists relative to the script:

```
/
├── asmExportReport.py
└── templates/
    ├── mave_output.html    # Jinja2 report template
    └── static/
        ├── images/         # Logos (gti_logo.png, ma_logo.png)
        └── css/            # Report styling
```

## Usage

Run the script from the command line. It is highly interactive and will guide you through the necessary steps.

```bash
python asmExportReport.py [options]
```

### Command Line Options

| Option | Description |
| :--- | :--- |
| `-key` | Prompt for the Google TI API key manually (overrides saved credentials). |
| `-adv` | Run in **Mandiant Advantage ASM** mode instead of Google TI mode. |
| `-concurrency N`| Set the maximum number of concurrent connections for fetching details (default: 100). |
| `-noverify` | Disable SSL certificate verification (use with caution). |
| `-debug` | Enable verbose debug logging to console. |
| `-nobanner` | Hide the startup disclaimer banner. |
| `-h`, `--help` | Show help message. |

### Interactive Workflow

1.  **Select Project**: Choose the ASM project you wish to analyze from the detected list.
2.  **Select Collection**: Choose specifically active collections to scan.
3.  **Select Data Type**: Choose to export Entities, Technologies, Issues, or standard "All".
4.  **Filter (Issues only)**: specific recent scan counts can be filtered to focus on fresh data.
5.  **Enrichment**: If issues are exported, the script automates fetching full details and asks to generate a CVE Vulnerability Report.
6.  **Upload**: Optionally archive and upload the entire output folder to a Google Cloud Storage bucket.

## Output

The tool creates a project-specific folder containing:

  * **CSV Exports**: Raw data for Entities, Assets, and Issues.
  * **Issue Details**: JSON files for every individual issue found.
  * **Vulnerability Report**: An interactive HTML dashboard (`*_cve_report.html`) and accompanying CSV summarizing all enriched CVE findings.

## Troubleshooting

  * **GCP Upload Fails**: Ensure you have authenticated your local environment by running `gcloud auth application-default login` before running the script.
  * **SSL Errors**: If running in a corporate environment with SSL inspection, try using the `-noverify` flag if you encounter certificate errors.
  * **Missing Templates**: Ensure the `templates/` folder is in the same directory as the script.
