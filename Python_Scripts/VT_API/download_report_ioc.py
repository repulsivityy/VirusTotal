import argparse
import json
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime
import requests

################
# Variables & Auth
################
if 'GTI_APIKEY' not in os.environ:
    print("Error: GTI_APIKEY environment variable is not set.")
    sys.exit(1)

# Supported collection types metadata
COLLECTION_METADATA = {
    "report": {
        "singular": "Report",
        "plural": "reports",
        "description": "Threat Intelligence Reports"
    },
    "campaign": {
        "singular": "Campaign",
        "plural": "campaigns",
        "description": "Threat Campaigns"
    },
    "threat-actor": {
        "singular": "Threat Actor",
        "plural": "threat_actors",
        "description": "Threat Actors / Threat Groups"
    },
    "malware-family": {
        "singular": "Malware Family",
        "plural": "malware_families",
        "description": "Malware Families"
    },
    "software-toolkit": {
        "singular": "Software Toolkit",
        "plural": "software_toolkits",
        "description": "Software Toolkits / Tools"
    },
    "vulnerability": {
        "singular": "Vulnerability",
        "plural": "vulnerabilities",
        "description": "Vulnerabilities (CVEs)"
    }
}

TYPE_ALIASES = {
    "report": "report",
    "reports": "report",
    "campaign": "campaign",
    "campaigns": "campaign",
    "threat-actor": "threat-actor",
    "threat_actor": "threat-actor",
    "threat-actors": "threat-actor",
    "threat_actors": "threat-actor",
    "actor": "threat-actor",
    "actors": "threat-actor",
    "malware-family": "malware-family",
    "malware_family": "malware-family",
    "malware-families": "malware-family",
    "malware": "malware-family",
    "malwares": "malware-family",
    "software-toolkit": "software-toolkit",
    "software_toolkit": "software-toolkit",
    "software-toolkits": "software-toolkit",
    "software_toolkits": "software-toolkit",
    "toolkit": "software-toolkit",
    "toolkits": "software-toolkit",
    "tool": "software-toolkit",
    "tools": "software-toolkit",
    "vulnerability": "vulnerability",
    "vulnerabilities": "vulnerability",
    "vuln": "vulnerability",
    "vulns": "vulnerability",
    "cve": "vulnerability",
    "cves": "vulnerability"
}

UOB_DIR = "uob_request"
UOB_SUBFOLDERS = {
    "report": "reports",
    "campaign": "campaign",
    "malware-family": "malware",
    "software-toolkit": "software_toolkits",
    "threat-actor": "threat_actor",
    "vulnerability": "vulnerability"
}

parser = argparse.ArgumentParser(description="Download GTI collections (reports, campaigns, threat actors, malware, toolkits, vulnerabilities) and curated IOCs.")
parser.add_argument("--date", "-d", type=str, help="Start date filter (e.g. 2024-01-01+ or 30d+)")
parser.add_argument("--type", "-t", type=str, help="Collection type to download (report, campaign, threat-actor, malware-family, software-toolkit, vulnerability)")
parser.add_argument("--output-dir", "-o", type=str, default=None, help="Target output directory (e.g. uob_request/campaign)")
parser.add_argument("--no-iocs", action="store_true", help="Skip downloading curated IOCs (only fetch collections & summary counts)")
args = parser.parse_args()

VT_APIKEY = os.environ['GTI_APIKEY']

# Collection type selection
COLLECTION_TYPE = args.type.strip().lower() if args.type else None
if not COLLECTION_TYPE:
    print("\nSupported collection types:")
    supported_keys = list(COLLECTION_METADATA.keys())
    for idx, key in enumerate(supported_keys, start=1):
        info = COLLECTION_METADATA[key]
        print(f"  {idx}) {key:<18} ({info['description']})")
    prompt_type = input("\nEnter Collection Type [1-6 or name] (default: report): ").strip().lower()
    if prompt_type.isdigit() and 1 <= int(prompt_type) <= len(supported_keys):
        COLLECTION_TYPE = supported_keys[int(prompt_type) - 1]
    else:
        COLLECTION_TYPE = prompt_type if prompt_type else "report"

# Normalize using aliases
COLLECTION_TYPE = TYPE_ALIASES.get(COLLECTION_TYPE, TYPE_ALIASES.get(COLLECTION_TYPE.replace('_', '-'), COLLECTION_TYPE))
if COLLECTION_TYPE not in COLLECTION_METADATA:
    print(f"[!] Unknown collection type '{COLLECTION_TYPE}'. Defaulting to 'report'.")
    COLLECTION_TYPE = "report"

TYPE_INFO = COLLECTION_METADATA[COLLECTION_TYPE]
TYPE_PLURAL = TYPE_INFO["plural"]
TYPE_LABEL = TYPE_INFO["singular"]

START_DATE = args.date.strip() if args.date else input("Enter Start Date (eg 2024-01-01+ or 30d+): ").strip()

# Input validation: check for digit+ without 'd' (e.g., '365+' matching epoch seconds)
if re.match(r'^\d+\+$', START_DATE):
    corrected_date = f"{START_DATE[:-1]}d+"
    print(f"[!] Warning: '{START_DATE}' matches Unix epoch timestamp (1970). Auto-correcting to '{corrected_date}'.")
    START_DATE = corrected_date

if args.no_iocs:
    SKIP_IOCS = True
else:
    # If not explicitly specified on CLI, prompt interactively if running in a terminal
    if sys.stdin.isatty():
        prompt_ioc = input(f"Download curated IOCs for each {COLLECTION_TYPE}? (y/n, default: y): ").strip().lower()
        SKIP_IOCS = prompt_ioc in ['n', 'no', 'false', '0']
    else:
        SKIP_IOCS = False

FILTERS = f'collection_type:{COLLECTION_TYPE} creation_date:{START_DATE} origin:"Google Threat Intelligence"'
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {
    "accept": "application/json",
    "x-apikey": VT_APIKEY,
    "x-tool": f"gti-{COLLECTION_TYPE}-ioc-downloader"
}

DATE_GENERATED = datetime.now().strftime("%Y-%m-%d")
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
SAFE_START_DATE = re.sub(r'[^a-zA-Z0-9_-]', '', START_DATE)

if args.output_dir:
    OUTPUT_DIR = args.output_dir
    os.makedirs(OUTPUT_DIR, exist_ok=True)
elif os.path.isdir(UOB_DIR) and COLLECTION_TYPE in UOB_SUBFOLDERS:
    OUTPUT_DIR = os.path.join(UOB_DIR, UOB_SUBFOLDERS[COLLECTION_TYPE])
    os.makedirs(OUTPUT_DIR, exist_ok=True)
else:
    OUTPUT_DIR = f"gti_{TYPE_PLURAL}_{SAFE_START_DATE}_{TIMESTAMP}"
    os.makedirs(OUTPUT_DIR, exist_ok=True)

# Subdirectory for individual JSON files
INDIVIDUAL_ITEMS_DIR = os.path.join(OUTPUT_DIR, TYPE_PLURAL)
if not SKIP_IOCS:
    os.makedirs(INDIVIDUAL_ITEMS_DIR, exist_ok=True)

RAW_IOCS_FILENAME = f"gti_{TYPE_PLURAL}_{SAFE_START_DATE}_to_{DATE_GENERATED}_raw_iocs.json"
RAW_ITEMS_FILENAME = f"gti_{TYPE_PLURAL}_{SAFE_START_DATE}_to_{DATE_GENERATED}_raw_{TYPE_PLURAL}.json"
SUMMARY_FILENAME = f"gti_{TYPE_PLURAL}_{SAFE_START_DATE}_to_{DATE_GENERATED}_summary.json"

RAW_IOCS_PATH = os.path.join(OUTPUT_DIR, RAW_IOCS_FILENAME)
RAW_ITEMS_PATH = os.path.join(OUTPUT_DIR, RAW_ITEMS_FILENAME)
SUMMARY_PATH = os.path.join(OUTPUT_DIR, SUMMARY_FILENAME)


################
# Step 1: List Reports
################
def list_reports(filters):
    """
    Fetches all report collections matching the specified filter,
    handling cursor pagination automatically.
    """
    encoded_filter = urllib.parse.quote(filters)
    url = f"{BASE_URL}/collections?filter={encoded_filter}&limit=40&order=creation_date-"
    reports = []
    cursor = None

    print(f"\n[+] Searching reports with filter: {filters}")

    while True:
        request_url = f"{url}&cursor={cursor}" if cursor else url
        response = requests.get(request_url, headers=HEADERS, timeout=30)
        response.raise_for_status()
        res_json = response.json()

        page_data = res_json.get("data", [])
        reports.extend(page_data)
        print(f"    Fetched {len(page_data)} reports (Total retrieved: {len(reports)})")

        cursor = res_json.get("meta", {}).get("cursor")
        if not cursor:
            break

    return reports


################
# Step 2: Download Report IOCs
################
def download_report_iocs(report_id):
    """
    Downloads curated IOCs for a specific report collection via the JSON export endpoint.
    """
    url = f"{BASE_URL}/collections/{report_id}/download/json"
    try:
        response = requests.get(url, headers=HEADERS, timeout=30)
        if response.status_code == 404:
            return {"files": [], "domains": [], "ip_addresses": [], "urls": []}
        response.raise_for_status()
        data = response.json() or {}
        return {
            "files": data.get("files") or [],
            "domains": data.get("domains") or [],
            "ip_addresses": data.get("ip_addresses") or [],
            "urls": data.get("urls") or []
        }
    except requests.exceptions.RequestException as e:
        print(f"    [!] Error downloading IOCs for {report_id}: {e}")
        return {"files": [], "domains": [], "ip_addresses": [], "urls": []}


################
# Step 3: Process & Display Summary
################
def print_summary_table(summary_reports, totals):
    """
    Prints a formatted ASCII summary table of collections and their IOC counts.
    """
    col_id_w = max(24, max((len(item["report_id"]) for item in summary_reports), default=24) + 2)
    col_name_w = 42
    col_num_w = 9

    header = (
        f"{TYPE_LABEL + ' ID':<{col_id_w}} "
        f"{TYPE_LABEL + ' Name':<{col_name_w}} "
        f"{'Files':>{col_num_w}} "
        f"{'Domains':>{col_num_w}} "
        f"{'IPs':>{col_num_w}} "
        f"{'URLs':>{col_num_w}} "
        f"{'Total':>{col_num_w}}"
    )
    separator = "-" * len(header)

    print("\n" + separator)
    print(f"GOOGLE THREAT INTELLIGENCE - {TYPE_LABEL.upper()} & IOC SUMMARY")
    print(separator)
    print(header)
    print(separator)

    for item in summary_reports:
        rep_id = item["report_id"]
        # Truncate long report names for clean table display
        rep_name = item["report_name"]
        if len(rep_name) > col_name_w:
            rep_name = rep_name[:col_name_w - 3] + "..."

        print(
            f"{rep_id:<{col_id_w}} "
            f"{rep_name:<{col_name_w}} "
            f"{item['files']:>{col_num_w}} "
            f"{item['domains']:>{col_num_w}} "
            f"{item['ip_addresses']:>{col_num_w}} "
            f"{item['urls']:>{col_num_w}} "
            f"{item['total_iocs']:>{col_num_w}}"
        )

    print(separator)
    print(
        f"{'GRAND TOTALS':<{col_id_w + col_name_w + 1}} "
        f"{totals['total_files']:>{col_num_w}} "
        f"{totals['total_domains']:>{col_num_w}} "
        f"{totals['total_ip_addresses']:>{col_num_w}} "
        f"{totals['total_urls']:>{col_num_w}} "
        f"{totals['grand_total_iocs']:>{col_num_w}}"
    )
    if totals.get('unique_files') != "N/A":
        print(
            f"{'UNIQUE TOTALS':<{col_id_w + col_name_w + 1}} "
            f"{totals['unique_files']:>{col_num_w}} "
            f"{totals['unique_domains']:>{col_num_w}} "
            f"{totals['unique_ip_addresses']:>{col_num_w}} "
            f"{totals['unique_urls']:>{col_num_w}} "
            f"{totals['unique_total_iocs']:>{col_num_w}}"
        )
    print(separator + "\n")


def main():
    print(f"[+] Output directory created: {OUTPUT_DIR}")

    # 1. Fetch all reports matching the filter
    reports = list_reports(FILTERS)
    print(f"\n[+] Total {TYPE_PLURAL} identified: {len(reports)}")

    if not reports:
        print(f"[!] No {TYPE_PLURAL} found matching the criteria.")
        return

    # 2. Download IOCs for each collection and compute breakdown
    summary_reports = []
    raw_reports_iocs = {}

    all_files = set()
    all_domains = set()
    all_ips = set()
    all_urls = set()

    total_files_count = 0
    total_domains_count = 0
    total_ips_count = 0
    total_urls_count = 0

    if SKIP_IOCS:
        print(f"\n[+] Extracting IOC counts directly from {COLLECTION_TYPE} metadata (--no-iocs active)...")
        for report in reports:
            report_id = report.get("id")
            attr = report.get("attributes", {})
            report_name = attr.get("name", f"Unnamed {TYPE_LABEL}")
            creation_date = attr.get("creation_date")

            files_count = attr.get("files_count") or 0
            domains_count = attr.get("domains_count") or 0
            ips_count = attr.get("ip_addresses_count") or 0
            urls_count = attr.get("urls_count") or 0
            report_total = files_count + domains_count + ips_count + urls_count

            total_files_count += files_count
            total_domains_count += domains_count
            total_ips_count += ips_count
            total_urls_count += urls_count

            summary_reports.append({
                "report_id": report_id,
                "report_name": report_name,
                "creation_date": creation_date,
                "files": files_count,
                "domains": domains_count,
                "ip_addresses": ips_count,
                "urls": urls_count,
                "total_iocs": report_total
            })

        totals = {
            f"total_{TYPE_PLURAL}": len(reports),
            "total_files": total_files_count,
            "total_domains": total_domains_count,
            "total_ip_addresses": total_ips_count,
            "total_urls": total_urls_count,
            "grand_total_iocs": total_files_count + total_domains_count + total_ips_count + total_urls_count,
            "unique_files": "N/A",
            "unique_domains": "N/A",
            "unique_ip_addresses": "N/A",
            "unique_urls": "N/A",
            "unique_total_iocs": "N/A"
        }
    else:
        print(f"\n[+] Downloading curated IOCs for each {COLLECTION_TYPE}...")
        for idx, report in enumerate(reports, start=1):
            report_id = report.get("id")
            report_name = report.get("attributes", {}).get("name", f"Unnamed {TYPE_LABEL}")
            creation_date = report.get("attributes", {}).get("creation_date")

            attr = report.get("attributes", {})
            meta_total = (attr.get("files_count") or 0) + (attr.get("domains_count") or 0) + (attr.get("ip_addresses_count") or 0) + (attr.get("urls_count") or 0)

            if meta_total > 0:
                print(f"    [{idx}/{len(reports)}] Fetching {meta_total} curated IOCs for: {report_id} ({report_name[:40]}...)")
                iocs = download_report_iocs(report_id)
                time.sleep(0.1)
            else:
                iocs = {"files": [], "domains": [], "ip_addresses": [], "urls": []}

            files = iocs.get("files") or []
            domains = iocs.get("domains") or []
            ip_addresses = iocs.get("ip_addresses") or []
            urls = iocs.get("urls") or []

            # Accumulate totals
            total_files_count += len(files)
            total_domains_count += len(domains)
            total_ips_count += len(ip_addresses)
            total_urls_count += len(urls)

            all_files.update(files)
            all_domains.update(domains)
            all_ips.update(ip_addresses)
            all_urls.update(urls)

            report_total = len(files) + len(domains) + len(ip_addresses) + len(urls)

            summary_reports.append({
                "report_id": report_id,
                "report_name": report_name,
                "creation_date": creation_date,
                "files": len(files),
                "domains": len(domains),
                "ip_addresses": len(ip_addresses),
                "urls": len(urls),
                "total_iocs": report_total
            })

            report_data = {
                "name": report_name,
                "creation_date": creation_date,
                "iocs": {
                    "files": files,
                    "domains": domains,
                    "ip_addresses": ip_addresses,
                    "urls": urls
                }
            }
            raw_reports_iocs[report_id] = report_data

            # Save individual item JSON inside the newly created folder
            indiv_item_path = os.path.join(INDIVIDUAL_ITEMS_DIR, f"{report_id}.json")
            with open(indiv_item_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)

        totals = {
            f"total_{TYPE_PLURAL}": len(reports),
            "total_files": total_files_count,
            "total_domains": total_domains_count,
            "total_ip_addresses": total_ips_count,
            "total_urls": total_urls_count,
            "grand_total_iocs": total_files_count + total_domains_count + total_ips_count + total_urls_count,
            "unique_files": len(all_files),
            "unique_domains": len(all_domains),
            "unique_ip_addresses": len(all_ips),
            "unique_urls": len(all_urls),
            "unique_total_iocs": len(all_files | all_domains | all_ips | all_urls)
        }

    # 3. Print Summary Table
    print_summary_table(summary_reports, totals)

    # 4. Save Raw Indicators JSON (combining all IOCs) if not SKIP_IOCS
    if not SKIP_IOCS:
        raw_output_data = {
            "metadata": {
                "collection_type": COLLECTION_TYPE,
                "filter": FILTERS,
                "start_date": START_DATE,
                "date_generated": DATE_GENERATED,
                f"total_{TYPE_PLURAL}": len(reports),
                "total_iocs": totals["grand_total_iocs"],
                "unique_iocs": totals["unique_total_iocs"]
            },
            "all_iocs_combined": {
                "files": sorted(list(all_files)),
                "domains": sorted(list(all_domains)),
                "ip_addresses": sorted(list(all_ips)),
                "urls": sorted(list(all_urls))
            },
            TYPE_PLURAL: raw_reports_iocs
        }

        with open(RAW_IOCS_PATH, "w", encoding="utf-8") as f:
            json.dump(raw_output_data, f, indent=2)
        print(f"[+] Combined Raw IOCs saved to: {RAW_IOCS_PATH}")
    else:
        print("[*] Curated IOC downloads skipped (--no-iocs). Raw IOC combined JSON omitted.")

    # 5. Save Summary JSON
    summary_output_data = {
        "metadata": {
            "collection_type": COLLECTION_TYPE,
            "filter": FILTERS,
            "start_date": START_DATE,
            "date_generated": DATE_GENERATED
        },
        "totals": totals,
        TYPE_PLURAL: summary_reports
    }

    with open(SUMMARY_PATH, "w", encoding="utf-8") as f:
        json.dump(summary_output_data, f, indent=2)
    print(f"[+] Summary report saved to: {SUMMARY_PATH}")

    # 6. Save Combined Raw Items JSON
    raw_items_output_data = {
        "metadata": {
            "collection_type": COLLECTION_TYPE,
            "filter": FILTERS,
            "start_date": START_DATE,
            "date_generated": DATE_GENERATED,
            f"total_{TYPE_PLURAL}": len(reports)
        },
        TYPE_PLURAL: reports
    }

    with open(RAW_ITEMS_PATH, "w", encoding="utf-8") as f:
        json.dump(raw_items_output_data, f, indent=2)
    print(f"[+] Combined Raw {TYPE_LABEL}s saved to: {RAW_ITEMS_PATH}")

    if not SKIP_IOCS:
        print(f"[+] Individual {COLLECTION_TYPE} JSONs saved to: {INDIVIDUAL_ITEMS_DIR}/")


if __name__ == "__main__":
    main()
