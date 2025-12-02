import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import os
from datetime import datetime
from typing import List, Dict, Optional, Union

# Global Constants
ASM_PROJECTS_URL = "https://www.virustotal.com/api/v3/asm/projects"

def get_session() -> requests.Session:
    """
    Creates and returns a requests.Session with retry logic configured.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def get_api_key() -> str:
    """
    Retrieves the Google Threat Intelligence API Key from the GTI_APIKEY environment variable.
    Validates that the API key is not empty.
    """
    api_key = "e95b32dbc09cf1453500956464707030e8b7b9100daad74c134ebab80249ac45"
    if not api_key:
        print("Error: GTI_APIKEY environment variable not set.")
        print("Please set the GTI_APIKEY environment variable with your Google Threat Intelligence API Key.")
        exit(1)
    return api_key

def get_target_emails() -> List[str]:
    """
    Prompts the user for target email address(es) to add.
    Supports a single email or a comma-separated list of emails.
    Validates email format (contains '@' and '.' in domain part).
    Asks for confirmation before returning.
    """
    while True:
        input_str = input("Enter the email address(es) of the user(s) to add (comma-separated): ").strip()
        if not input_str:
            print("Email input cannot be empty.")
            continue
        
        raw_emails = [e.strip() for e in input_str.split(',') if e.strip()]
        
        if not raw_emails:
             print("No valid emails found.")
             continue

        valid_emails = []
        invalid_emails = []

        for email in raw_emails:
            if email.count('@') == 1:
                local_part, domain_part = email.split('@')
                if '.' in domain_part:
                    valid_emails.append(email)
                else:
                    invalid_emails.append(email)
            else:
                invalid_emails.append(email)
        
        if invalid_emails:
            print(f"\nWarning: The following inputs do not look like valid emails:")
            for email in invalid_emails:
                print(f" - {email}")
            
            if not valid_emails:
                print("No valid emails provided. Please try again.")
                continue

            proceed = input(f"\nDo you want to proceed with the {len(valid_emails)} valid email(s)? (y/n): ").lower().strip()
            if proceed != 'y':
                continue

        print(f"\nYou entered the following {len(valid_emails)} valid email(s):")
        for email in valid_emails:
            print(f" - {email}")
            
        confirm = input("Is this correct? (y/n): ").lower().strip()
        if confirm == 'y':
            return valid_emails
        elif confirm == 'n':
            print("Okay, let's try again.")
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

def get_user_role() -> str:
    """
    Prompts the user to select the role for the new user(s).
    Options: 'member' (default) or 'owner'.
    """
    while True:
        role = input("Enter the role for the user(s) ('member' or 'owner') [default: member]: ").lower().strip()
        if role == '' or role == 'member':
            return 'member'
        elif role == 'owner':
            return 'owner'
        else:
            print("Invalid role. Please enter 'member' or 'owner'.")

def get_all_projects(api_key: str) -> Optional[List[Dict[str, str]]]:
    """
    Retrieves all ASM projects from GTI.
    Returns a list of dictionaries with project name and ID.
    """
    projects = []
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    print("Retrieving ASM projects...")
    session = get_session()
    try:
        response = session.get(ASM_PROJECTS_URL, headers=headers)
        response.raise_for_status() # Raise an exception for HTTP errors
        data = response.json()
        
        for project in data["result"]:
            projects.append({
                "id": project["uuid"],
                "name": project["name"]
            })
        
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error occurred: {e}")
        try:
            print(f"Response body: {response.json()}")
        except:
            print(f"Response body: {response.text}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None
    
    print(f"Found {len(projects)} projects.")
    return projects

def select_projects(project_list: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Prompts the user to select projects from a list.
    Handles 'all', ranges (e.g., '1-5'), and comma-separated indices (e.g., '1,3,5').
    Returns a list of selected project dictionaries.
    """
    selected_projects = []
    while True:
        print("\n--- Select Projects ---")
        selection_input = input("Enter project numbers (e.g., '1,3,5'), a range (e.g., '1-5'), or 'all': ").lower().strip()

        if selection_input == "all":
            selected_projects = project_list
            break
        else:
            indices = set()
            valid_input = True
            for part in selection_input.split(','):
                part = part.strip()
                if '-' in part:
                    try:
                        start, end = map(int, part.split('-'))
                        if not (1 <= start <= end <= len(project_list)):
                            print(f"Invalid range: {part}. Please use valid project numbers (1-{len(project_list)}).")
                            valid_input = False
                            break
                        for i in range(start, end + 1):
                            indices.add(i - 1) # Convert to 0-based index
                    except ValueError:
                        print(f"Invalid range format: {part}. Use 'start-end'.")
                        valid_input = False
                        break
                else:
                    try:
                        index = int(part)
                        if not (1 <= index <= len(project_list)):
                            print(f"Invalid project number: {index}. Please use valid project numbers (1-{len(project_list)}).")
                            valid_input = False
                            break
                        indices.add(index - 1) # Convert to 0-based index
                    except ValueError:
                        print(f"Invalid input: {part}. Please enter numbers, ranges, or 'all'.")
                        valid_input = False
                        break
            
            if valid_input:
                selected_projects = [project_list[i] for i in sorted(list(indices))]
                if selected_projects:
                    break
                else:
                    print("No projects selected. Please try again.")
            
    print("\n--- Selected Projects for User Addition ---")
    for i, project in enumerate(selected_projects):
        print(f" {i+1}. {project['name']}, ID: {project['id']}")
    
    confirm_selection = input("Is this selection correct? (y/n): ").lower().strip()
    if confirm_selection == 'y':
        return selected_projects
    else:
        print("Restarting project selection.")
        return select_projects(project_list) # Recursively call for re-selection

def add_user_to_projects(emails: List[str], role: str, projects: List[Dict[str, str]], api_key: str) -> List[Dict[str, Union[str, dict]]]:
    """
    Adds the target email(s) to the specified projects using the bulk add endpoint.
    """
    print(f"\n--- Adding {len(emails)} user(s) to selected projects as '{role}' ---")
    results = []
    
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    session = get_session()

    for project in projects:
        project_id = project["id"]
        project_name = project["name"]
        url = f"{ASM_PROJECTS_URL}/{project_id}/users/bulk"
        
        payload = {
            "emails": emails,
            "role": role,
            "project_group_uuid": None
        }

        print(f"Attempting to add users to project: {project_name} (ID: {project_id})...")
        try:
            response = session.post(url, headers=headers, json=payload)
            response.raise_for_status()
            
            # Basic validation of success based on sample response structure
            data = response.json()
            if data.get("success") is True:
                print(f"Successfully added users to {project_name}.")
                results.append({"project": project_name, "status": "success"})
            else:
                print(f"Unexpected response format from {project_name}: {data}")
                results.append({"project": project_name, "status": "unknown", "response": data})

        except requests.exceptions.HTTPError as e:
            print(f"Error adding users to {project_name}: {e}")
            try:
                print(f"Response body: {response.json()}")
                results.append({"project": project_name, "status": "failure", "error": response.json()})
            except:
                print(f"Response body: {response.text}")
                results.append({"project": project_name, "status": "failure", "error": response.text})
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while adding to {project_name}: {e}")
            results.append({"project": project_name, "status": "failure", "error": str(e)})
            
    return results

def main():
    print("--- GTI ASM User Manager ---")
    
    # Step 1: Input Collection
    api_key = get_api_key()
    target_emails = get_target_emails()
    user_role = get_user_role()
    
    print("\n--- Verification ---")
    print(f"API Key captured: {'*' * (len(api_key) - 4) + api_key[-4:] if len(api_key) > 4 else '****'}")
    print(f"Target Emails: {', '.join(target_emails)}")
    print(f"User Role: {user_role}")

    # Step 2: Retrieve ASM Projects
    project_list = get_all_projects(api_key)
    if project_list:
        print("\n--- Retrieved Projects ---")
        for i, project in enumerate(project_list):
            print(f" {i+1}. {project['name']}, ID: {project['id']}")

        # Step 3: Project Selection Logic
        selected_projects = select_projects(project_list)
        if selected_projects:
            print("\nProceeding with selected projects...")
            # Step 4: Execution Loop
            results = add_user_to_projects(target_emails, user_role, selected_projects, api_key)
            
            # Step 5: Reporting
            print("\n--- Execution Summary ---")
            print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 30)
            for res in results:
                status = res['status'].upper()
                print(f"Project: {res['project']}")
                print(f"Status:  {status}")
                if status != 'SUCCESS' and 'error' in res:
                    print(f"Error:   {res['error']}")
                print("-" * 30)
        else:
            print("No projects selected. Exiting.")

if __name__ == "__main__":
    main()
