# ==========================================
# Python code to export Livehunt rules from VT and import into GTI
# Date: Jun 2026
# 
# Usage
# - Configure API Keys in environment variables
# -- export VT_APIKEY=YOUR_API_KEY // This is from the original tenant (VT)
# -- export GTI_APIKEY=YOUR_API_KEY // This is from the target tenant (GTI)
# - Run the script
# - Select an option from the Menu:
#   - View Livehunt rules
#   - Export Livehunt rules
#   - Import Livehunt rules
#   - Workflow (Export and Import at the same time)
# ==========================================

import requests
import csv
import sys
import ast
import os
from urllib.parse import quote

# ==========================================
# Variables
# ==========================================
VT_API_KEY = os.getenv("VT_APIKEY")
GTI_API_KEY = os.getenv("GTI_APIKEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"
GTI_BASE_URL = "https://www.virustotal.com/api/v3" 

CSV_FILENAME = "livehunt_rules_export.csv"
TOOL_HEADER = "livehunt-migrator"

# ==========================================
# Helper Functions
# ==========================================
def get_headers(api_key, is_post=False):
    """Returns standard headers. content-type is strictly for POST requests."""
    headers = {
        "x-apikey": api_key,
        "x-tool": TOOL_HEADER,
        "accept": "application/json"
    }
    if is_post:
        headers["content-type"] = "application/json"
    return headers

def print_insights(operation, success_count, fail_count, errors):
    """Outputs a clean summary of the operation."""
    print(f"\n" + "="*50)
    print(f"[{operation.upper()}] OPERATION INSIGHTS")
    print(f"="*50)
    print(f"Total Successful : {success_count}")
    print(f"Total Failed     : {fail_count}")
    
    if errors:
        print("\nError Log:")
        for err in errors:
            print(f" - {err}")
    print("="*50 + "\n")

def save_to_csv(data_list, filename, operation_name):
    """Helper to save extracted data to CSV."""
    if not data_list:
        print(f"[-] No rulesets found/processed for {operation_name}.")
        return False

    fieldnames = ['id', 'name', 'enabled', 'limit', 'match_object_type', 'notification_emails', 'rules']
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data_list)
        
        print_insights(f"{operation_name} Export", len(data_list), 0, [])
        return True
    except IOError as e:
        print(f"[!] Error writing to CSV: {e}")
        return False

# ==========================================
# View Operations
# ==========================================
def show_all_rules(api_key, role_filter='all'):
    """Fetches and prints a table of ALL Livehunt rules filtered by role."""
    print(f"\n[*] Fetching rulesets from Source (Filter: {role_filter})...")
    url = f"{VT_BASE_URL}/intelligence/hunting_rulesets?limit=40"
    
    # Map role_filter to set of roles to match
    if role_filter == 'owner':
        allowed_roles = {'owner'}
    elif role_filter == 'editor':
        allowed_roles = {'editor'}
    elif role_filter == 'viewer':
        allowed_roles = {'viewer'}
    else:
        allowed_roles = None
        
    try:
        print(f"\n{'-'*95}")
        print(f"{'RULE ID':<15} | {'NAME':<40} | {'ENABLED':<10} | {'ROLE'}")
        print(f"{'-'*95}")
        
        count = 0
        with requests.Session() as session:
            session.headers.update(get_headers(api_key, is_post=False))
            while url:
                response = session.get(url)
                response.raise_for_status()
                payload = response.json()
                
                for item in payload.get('data', []):
                    attrs = item.get('attributes', {})
                    ctx = item.get('context_attributes', {})
                    
                    role = ctx.get('role', 'unknown')
                    if allowed_roles is not None and role not in allowed_roles:
                        continue
                        
                    rule_id = item.get('id', 'N/A')
                    name = attrs.get('name', 'Unnamed')[:40]
                    enabled = str(attrs.get('enabled', False))
                    
                    print(f"{rule_id:<15} | {name:<40} | {enabled:<10} | {role}")
                    count += 1
                    
                url = payload.get('links', {}).get('next')
            
        print(f"{'-'*95}")
        print(f"Total Rules Displayed: {count}\n")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching rules: {e}")

def show_specific_rule(api_key, rule_id):
    """Fetches and prints details for a specific rule ID."""
    print(f"\n[*] Fetching details for Rule ID: {rule_id}")
    url = f"{VT_BASE_URL}/intelligence/hunting_rulesets/{quote(rule_id)}"
    
    try:
        response = requests.get(url, headers=get_headers(api_key, is_post=False))
        response.raise_for_status()
        item = response.json().get('data', {})
        attrs = item.get('attributes', {})
        
        print(f"\n{'='*50}")
        print(f" RULE DETAILS: {attrs.get('name', 'Unnamed')}")
        print(f" ID: {item.get('id')}")
        print(f" Enabled: {attrs.get('enabled')}")
        print(f" Match Type: {attrs.get('match_object_type')}")
        print(f" Notification Emails: {attrs.get('notification_emails')}")
        print(f"{'='*50}")
        print("YARA TEXT:\n")
        print(attrs.get('rules', 'No rule text found.'))
        print(f"{'='*50}\n")
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to fetch rule {rule_id}. Error: {e}")

# ==========================================
# Core Export Operations
# ==========================================
def export_rules_bulk(api_key, csv_file, role_filter='all', status_filter='all'):
    """Fetches ALL rules and applies local filtering for export."""
    print(f"\n[*] Initiating Bulk Export (Role: {role_filter}, Status: {status_filter})...")
    url = f"{VT_BASE_URL}/intelligence/hunting_rulesets?limit=40"
    extracted_data = []
    
    # Map role_filter to set of roles to match
    if role_filter == 'owner':
        allowed_roles = {'owner'}
    elif role_filter == 'editor':
        allowed_roles = {'editor'}
    elif role_filter == 'viewer':
        allowed_roles = {'viewer'}
    else:
        allowed_roles = None
        
    try:
        with requests.Session() as session:
            session.headers.update(get_headers(api_key, is_post=False))
            while url:
                response = session.get(url)
                response.raise_for_status()
                payload = response.json()
                
                for item in payload.get('data', []):
                    attrs = item.get('attributes', {})
                    ctx = item.get('context_attributes', {})
                    
                    # Filter by role
                    role = ctx.get('role', 'unknown')
                    if allowed_roles is not None and role not in allowed_roles:
                        continue
                        
                    # Filter by enabled status
                    is_enabled = attrs.get('enabled', False)
                    if status_filter == 'enabled' and not is_enabled:
                        continue
                        
                    extracted_data.append({
                        'id': item.get('id'),
                        'name': attrs.get('name', 'Unnamed_Rule'),
                        'enabled': is_enabled,
                        'limit': attrs.get('limit', 100),
                        'match_object_type': attrs.get('match_object_type', 'file'),
                        'notification_emails': attrs.get('notification_emails', []),
                        'rules': attrs.get('rules', '')
                    })
                    
                url = payload.get('links', {}).get('next')
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Critical Error fetching from VT: {e}")
        return False

    return save_to_csv(extracted_data, csv_file, "Bulk")

def export_specific_rules(api_key, csv_file, rule_ids):
    """Fetches specific rules by ID and exports them."""
    print(f"\n[*] Initiating Targeted Export for {len(rule_ids)} rule(s)...")
    extracted_data = []
    failed_count = 0
    errors = []
    
    with requests.Session() as session:
        session.headers.update(get_headers(api_key, is_post=False))
        for r_id in rule_ids:
            url = f"{VT_BASE_URL}/intelligence/hunting_rulesets/{quote(r_id)}"
            try:
                response = session.get(url)
                response.raise_for_status()
                item = response.json().get('data', {})
                attrs = item.get('attributes', {})
                
                extracted_data.append({
                    'id': item.get('id'),
                    'name': attrs.get('name', 'Unnamed_Rule'),
                    'enabled': attrs.get('enabled', True),
                    'limit': attrs.get('limit', 100),
                    'match_object_type': attrs.get('match_object_type', 'file'),
                    'notification_emails': attrs.get('notification_emails', []),
                    'rules': attrs.get('rules', '')
                })
                print(f" [+] Queued Rule ID: {r_id} ({attrs.get('name')})")
            except requests.exceptions.RequestException as e:
                failed_count += 1
                err_msg = f"Failed to fetch {r_id}: {e}"
                print(f" [!] {err_msg}")
                errors.append(err_msg)
            
    if failed_count > 0:
        print_insights("Targeted Fetch", len(extracted_data), failed_count, errors)
        
    return save_to_csv(extracted_data, csv_file, "Targeted")

# ==========================================
# Core Import Operations
# ==========================================
def import_rules(api_key, csv_file):
    """Reads rules from CSV and posts them to target API."""
    print(f"\n[*] Initiating Import to Target from {csv_file}...")
    url = f"{GTI_BASE_URL}/intelligence/hunting_rulesets"
    ruleset_data = []
    
    try:
        with open(csv_file, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                ruleset_data.append(row)
    except FileNotFoundError:
        print(f"[!] Could not find {csv_file}. Please run an Export first.")
        return False

    success, fail = 0, 0
    error_log = []

    with requests.Session() as session:
        session.headers.update(get_headers(api_key, is_post=True))
        for ruleset in ruleset_data:
            try:
                try:
                    emails = ast.literal_eval(ruleset['notification_emails'])
                except (ValueError, SyntaxError):
                    emails = []

                is_enabled = str(ruleset['enabled']).strip().lower() == 'true'

                payload = {
                    "data": {
                        "type": "hunting_ruleset",
                        "attributes": {
                            "name": ruleset['name'],
                            "enabled": is_enabled,
                            "limit": int(ruleset['limit']),
                            "rules": ruleset['rules'],
                            "notification_emails": emails,
                            "match_object_type": ruleset['match_object_type']
                        }
                    }
                }
                
                response = session.post(url, json=payload)
                response.raise_for_status()
                
                new_id = response.json().get('data', {}).get('id', 'Unknown')
                print(f" [+] Migrated: {ruleset['name']} -> New GTI ID: {new_id}")
                success += 1
                
            except requests.exceptions.RequestException as e:
                err_msg = f"{ruleset['name']} - API Error: {e}"
                if e.response is not None:
                    err_msg += f" | {e.response.text}"
                error_log.append(err_msg)
                fail += 1
            except Exception as e:
                error_log.append(f"{ruleset.get('name', 'Unknown')} - Local Error: {e}")
                fail += 1

    print_insights("Import", success, fail, error_log)
    return True

# ==========================================
# Main Execution Menu
# ==========================================
def main():
    if not VT_API_KEY:
        print("[!] Warning: VT_APIKEY environment variable is not set. View/Export options will fail.")
    if not GTI_API_KEY:
        print("[!] Warning: GTI_APIKEY environment variable is not set. Import options will fail.")

    while True:
        print("\n" + "="*50)
        print(" Livehunt Ruleset Migration & Management Utility")
        print("="*50)
        print("--- View ---")
        print(" 1) Show ALL Livehunt rules")
        print(" 2) Show a SPECIFIC rule (by ID)")
        print("--- Export ---")
        print(" 3) Export rules to CSV (with filters)")
        print(" 4) Export SPECIFIC rules to CSV (by ID)")
        print("--- Import ---")
        print(" 5) Import rules from CSV to Target (GTI)")
        print("--- Workflows ---")
        print(" 6) Full Bulk Pipeline (Export ALL Enabled -> Import)")
        print(" 7) Targeted Pipeline  (Export SPECIFIC -> Import)")
        print(" 8) Exit")
        print("="*50)
        
        choice = input("Select an option (1-8): ").strip()
        
        if choice == '1':
            if not VT_API_KEY:
                print("[!] Error: VT_APIKEY environment variable is not set.")
                continue
            role_filter = input("Filter by role (owner/editor/viewer/all) [all]: ").strip().lower()
            if role_filter not in ('owner', 'editor', 'viewer', 'all', ''):
                print("[!] Invalid filter choice. Showing all.")
                role_filter = 'all'
            if not role_filter:
                role_filter = 'all'
            show_all_rules(VT_API_KEY, role_filter)
            
        elif choice == '2':
            if not VT_API_KEY:
                print("[!] Error: VT_APIKEY environment variable is not set.")
                continue
            rule_id = input("Enter the Rule ID to view: ").strip()
            if rule_id:
                show_specific_rule(VT_API_KEY, rule_id)
            else:
                print("[!] Invalid ID.")
                
        elif choice == '3':
            if not VT_API_KEY:
                print("[!] Error: VT_APIKEY environment variable is not set.")
                continue
            role_filter = input("Filter by role (owner/editor/viewer/all) [all]: ").strip().lower()
            if role_filter not in ('owner', 'editor', 'viewer', 'all', ''):
                print("[!] Invalid filter choice. Using all.")
                role_filter = 'all'
            if not role_filter:
                role_filter = 'all'
                
            status_filter = input("Filter by status (enabled/all) [all]: ").strip().lower()
            if status_filter not in ('enabled', 'all', ''):
                print("[!] Invalid status choice. Using all.")
                status_filter = 'all'
            if not status_filter:
                status_filter = 'all'
                
            export_rules_bulk(VT_API_KEY, CSV_FILENAME, role_filter, status_filter)
            
        elif choice == '4':
            if not VT_API_KEY:
                print("[!] Error: VT_APIKEY environment variable is not set.")
                continue
            ids_input = input("Enter Rule IDs separated by commas: ").strip()
            if ids_input:
                rule_ids = [r_id.strip() for r_id in ids_input.split(',') if r_id.strip()]
                export_specific_rules(VT_API_KEY, CSV_FILENAME, rule_ids)
            else:
                print("[!] No IDs provided.")
                
        elif choice == '5':
            if not GTI_API_KEY:
                print("[!] Error: GTI_APIKEY environment variable is not set.")
                continue
            import_rules(GTI_API_KEY, CSV_FILENAME)
            
        elif choice == '6':
            if not VT_API_KEY or not GTI_API_KEY:
                print("[!] Error: Both VT_APIKEY and GTI_APIKEY environment variables must be set.")
                continue
            if export_rules_bulk(VT_API_KEY, CSV_FILENAME, role_filter='owner', status_filter='enabled'):
                import_rules(GTI_API_KEY, CSV_FILENAME)
                
        elif choice == '7':
            if not VT_API_KEY or not GTI_API_KEY:
                print("[!] Error: Both VT_APIKEY and GTI_APIKEY environment variables must be set.")
                continue
            ids_input = input("Enter Rule IDs separated by commas for the pipeline: ").strip()
            if ids_input:
                rule_ids = [r_id.strip() for r_id in ids_input.split(',') if r_id.strip()]
                if export_specific_rules(VT_API_KEY, CSV_FILENAME, rule_ids):
                    import_rules(GTI_API_KEY, CSV_FILENAME)
            else:
                print("[!] No IDs provided. Pipeline aborted.")
                
        elif choice == '8':
            print("Exiting utility. Goodbye!")
            sys.exit(0)
            
        else:
            print("[!] Invalid selection. Please choose a number between 1 and 8.")

if __name__ == "__main__":
    main()