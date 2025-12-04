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
    #api_key = os.getenv("VT_API_KEY") #for testing...
    api_key = os.getenv("GTI_APIKEY")
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
                "uuid": project["uuid"],
                "id": project["id"], # Numeric ID needed for collections
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
        project_uuid = project["uuid"]
        project_name = project["name"]
        url = f"{ASM_PROJECTS_URL}/{project_uuid}/users/bulk"
        
        payload = {
            "emails": emails,
            "role": role,
            "project_group_uuid": None
        }

        print(f"Attempting to add users to project: {project_name} (ID: {project_uuid})...")
        try:
            response = session.post(url, headers=headers, json=payload)
            response.raise_for_status()
            
            # Basic validation of success based on sample response structure
            data = response.json()
            if data.get("success") is True:
                print(f"Successfully added users to {project_name}.")
                results.append({
                    "project": project_name, 
                    "status": "success",
                    "added_users": data.get("result", []),
                    "project_data": project
                })
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

def get_project_users(project_id: str, api_key: str) -> Optional[List[Dict]]:
    """
    Retrieves all users for a specific ASM project.
    """
    url = f"{ASM_PROJECTS_URL}/{project_id}/users"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    
    session = get_session()
    try:
        response = session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data.get("result", [])
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving users for project {project_id}: {e}")
        return None

def display_project_users(project_name: str, users: List[Dict]):
    """
    Formats and prints the list of users for a project.
    """
    print(f"\n--- Users in Project: {project_name} ---")
    if not users:
        print("No users found.")
        return
        
    print(f"{'Email':<40} {'Role':<15} {'Name':<30}")
    print("-" * 85)
    for user in users:
        email = user.get('email', 'N/A')
        role = user.get('role', 'N/A')
        first = user.get('first_name', '')
        last = user.get('last_name', '')
        name = f"{first} {last}".strip()
        if not name:
            name = user.get('name', 'N/A')
            
        print(f"{email:<40} {role:<15} {name:<30}")

def get_project_collections(project_numeric_id: int, api_key: str) -> List[Dict]:
    """
    Retrieves all collections for a specific ASM project using its numeric ID.
    """
    url = "https://www.virustotal.com/api/v3/asm/user_collections"
    headers = {
        "x-apikey": api_key,
        "PROJECT-ID": str(project_numeric_id),
        "Accept": "application/json"
    }
    
    session = get_session()
    try:
        response = session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data.get("result", [])
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving collections for project ID {project_numeric_id}: {e}")
        return []

def add_user_to_collection(collection_uuid: str, user_id: int, role: str, api_key: str) -> bool:
    """
    Adds a user (by numeric user_id) to a collection (by UUID).
    """
    url = f"https://www.virustotal.com/api/v3/asm/user_collections/{collection_uuid}/collection_project_users"
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = {
        "project_user_id": user_id,
        "role": role
    }
    
    session = get_session()
    try:
        response = session.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json().get("success", False)
    except requests.exceptions.RequestException as e:
        print(f"Error adding user {user_id} to collection {collection_id}: {e}")
        try:
            print(f"Response: {response.text}")
        except:
            pass
        return False

def select_collections(collections: List[Dict]) -> List[Dict]:
    """
    Prompts user to select collections from a list.
    """
    if not collections:
        return []
        
    print("\nAvailable Collections:")
    for i, col in enumerate(collections):
        print(f" {i+1}. {col.get('name', 'Unnamed')} (ID: {col.get('id')})")
        
    while True:
        selection = input("Enter collection numbers (e.g. '1,3'), 'all', or 'none': ").lower().strip()
        if selection == 'none':
            return []
        if selection == 'all':
            return collections
            
        selected = []
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            for idx in indices:
                if 0 <= idx < len(collections):
                    selected.append(collections[idx])
            if selected:
                return selected
            print("No valid collections selected.")
        except ValueError:
            print("Invalid input.")

def main():
    print("--- GTI ASM User Manager ---")
    
    api_key = get_api_key()
    
    print("\nSelect Mode:")
    print("1. Add Users to Projects")
    print("2. List Users in Projects")
    mode = input("Enter choice (1 or 2): ").strip()
    
    if mode == '1':
        # Step 1: Input Collection
        target_emails = get_target_emails()
        user_role = get_user_role()
        
        print(f"\n--- Verification ---")
        print(f"API Key captured: {'*' * (len(api_key) - 4) + api_key[-4:] if len(api_key) > 4 else '****'}")
        print(f"Target Emails: {', '.join(target_emails)}")
        print(f"User Role: {user_role}")

        # Step 2: Retrieve ASM Projects
        project_list = get_all_projects(api_key)
        if project_list:
            print("\n--- Retrieved Projects ---")
            for i, project in enumerate(project_list):
                print(f" {i+1}. {project['name']}, ID: {project['uuid']}")

            # Step 3: Project Selection Logic
            selected_projects = select_projects(project_list)
            if selected_projects:
                print("\nProceeding with selected projects...")
                # Step 4: Execution Loop
                results = add_user_to_projects(target_emails, user_role, selected_projects, api_key)
                
                # Step 5: Reporting & Collection Assignment
                print("\n--- Execution Summary ---")
                print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print("-" * 30)
                
                for res in results:
                    status = res['status'].upper()
                    project_name = res['project']
                    print(f"Project: {project_name}")
                    print(f"Status:  {status}")
                    
                    if status == 'SUCCESS':
                        # Handle Collection Assignment if Role is Member
                        if user_role == 'member':
                            added_users = res.get('added_users', [])
                            project_data = res.get('project_data')
                            
                            if added_users and project_data:
                                print(f"\n[Collection Setup] for {project_name}")
                                collections = get_project_collections(project_data['id'], api_key)
                                
                                if collections:
                                    selected_cols = select_collections(collections)
                                    if selected_cols:
                                        col_role = input("Enter role for collections (viewer/analyst/admin) [default: viewer]: ").lower().strip() or 'viewer'
                                        
                                        print(f"Adding {len(added_users)} users to {len(selected_cols)} collections...")
                                        for user in added_users:
                                            user_id = user.get('id') # Numeric ID
                                            user_email = user.get('email')
                                            
                                            for col in selected_cols:
                                                success = add_user_to_collection(col['uuid'], user_id, col_role, api_key)
                                                if success:
                                                    print(f" + Added {user_email} to {col.get('name')}")
                                                else:
                                                    print(f" ! Failed to add {user_email} to {col.get('name')}")
                                    else:
                                        print("Skipping collection assignment (none selected).")
                                else:
                                    print("No collections found in this project.")
                        else:
                            print("Skipping collection assignment (User is Owner).")
                            
                    elif 'error' in res:
                        print(f"Error:   {res['error']}")
                    print("-" * 30)
                
                # Step 6: Optional Listing
                list_now = input("\nDo you want to list users for these projects now? (y/n): ").lower().strip()
                if list_now == 'y':
                    for project in selected_projects:
                        users = get_project_users(project['uuid'], api_key)
                        if users is not None:
                            display_project_users(project['name'], users)
            else:
                print("No projects selected. Exiting.")
                
    elif mode == '2':
        # List Users Mode
        project_list = get_all_projects(api_key)
        if project_list:
            print("\n--- Retrieved Projects ---")
            for i, project in enumerate(project_list):
                print(f" {i+1}. {project['name']}, ID: {project['uuid']}")

            selected_projects = select_projects(project_list)
            if selected_projects:
                for project in selected_projects:
                    users = get_project_users(project['uuid'], api_key)
                    if users is not None:
                        display_project_users(project['name'], users)
            else:
                print("No projects selected. Exiting.")
    else:
        print("Invalid selection. Exiting.")

if __name__ == "__main__":
    main()
