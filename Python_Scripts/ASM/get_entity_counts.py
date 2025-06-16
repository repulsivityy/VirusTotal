import requests
import os
import json

# --- Configuration ---
# It's recommended to set your API key as an environment variable
# for security purposes.
# In your terminal (Linux/macOS): export GTI_APIKEY='your_api_key_here'
# In your terminal (Windows): set GTI_APIKEY='your_api_key_here'
API_KEY = os.getenv("GTI_APIKEY")

BASE_URL = "https://www.virustotal.com/api/v3/asm"

def main():
    """
    Main function to orchestrate the process of fetching projects,
    getting collection data, and printing the final report.
    """
    if not API_KEY or API_KEY == "<gti_api_key>":
        print("Error: API key is not set.")
        print("Please set the GTI_APIKEY environment variable or edit the script to include your key.")
        return

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    try:
        # 1. Get all projects
        print("Fetching projects...")
        projects_url = f"{BASE_URL}/projects"
        response = requests.get(projects_url, headers=headers)
        response.raise_for_status()  # Raises an exception for bad status codes (4xx or 5xx)
        projects = response.json().get("result", [])
        
        if not projects:
            print("No projects found for this API key.")
            return

        project_entity_data = []

        # 2. Iterate through each project to get its collections
        for project in projects:
            project_id = project.get("id")
            project_name = project.get("name")
            print(f"\nProcessing project: '{project_name}' (ID: {project_id})")

            # Prepare headers for the collection request, including the project ID
            collection_headers = headers.copy()
            collection_headers["PROJECT-ID"] = str(project_id)

            collections_url = f"{BASE_URL}/user_collections"
            collections_response = requests.get(collections_url, headers=collection_headers)
            collections_response.raise_for_status()
            
            collections = collections_response.json().get("result", [])
            
            # 3. Sum entities from non-deleted collections
            total_entities_for_project = 0
            for collection in collections:
                # As requested, ignore collections where 'deleted' is true
                if not collection.get("deleted", False):
                    entity_count = collection.get("total_entity_count", 0)
                    total_entities_for_project += entity_count
                    print(f"  - Found active collection '{collection.get('name')}': {entity_count} entities")
            
            print(f"  -> Total live entities for '{project_name}': {total_entities_for_project}")
            project_entity_data.append({
                "name": project_name,
                "total_entities": total_entities_for_project
            })

        # 4. Calculate grand total and print the final results table
        grand_total = sum(item['total_entities'] for item in project_entity_data)
        print_results_table(project_entity_data, grand_total)

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP Error: {http_err}")
        print(f"Response Body: {http_err.response.text}")
    except requests.exceptions.RequestException as req_err:
        print(f"Request Error: {req_err}")
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON from the response.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def print_results_table(data, grand_total):
    """
    Formats and prints the collected data in a table, including a grand total.
    """
    if not data:
        print("\nNo data to display.")
        return

    print("\n\n--- Final Entity Count Summary ---")

    # Determine column widths for nice formatting
    name_col_width = max([len(item['name']) for item in data] + [len("Project Name"), len("Total")])
    entities_col_width = max([len(str(item['total_entities'])) for item in data] + [len("Total Entities"), len(str(grand_total))])

    # Header
    header = f"| {'Project Name'.ljust(name_col_width)} | {'Total Entities'.ljust(entities_col_width)} |"
    separator = f"+-{'-' * name_col_width}-+-{'-' * entities_col_width}-+"
    
    print(separator)
    print(header)
    print(separator)

    # Rows
    for item in data:
        name = item['name'].ljust(name_col_width)
        entities = str(item['total_entities']).ljust(entities_col_width)
        print(f"| {name} | {entities} |")

    # Total Row
    print(separator)
    total_label = "Total".ljust(name_col_width)
    total_value = str(grand_total).ljust(entities_col_width)
    print(f"| {total_label} | {total_value} |")
    print(separator)


if __name__ == "__main__":
    main()