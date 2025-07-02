# File: test_logic.py

import json

# This mock data simulates the JSON response from the API
# Note: "duplicate-id" appears twice with different modification dates.
MOCK_API_DATA = {
    "iocs": [
        {
            "data": {
                "id": "unique-id-1",
                "type": "url",
                "attributes": {
                    "last_modification_date": 1700000000 # An older timestamp
                }
            }
        },
        {
            "data": {
                "id": "duplicate-id",
                "type": "url",
                "attributes": {
                    "last_modification_date": 1600000000, # The OLD version of the duplicate
                    "positives": 10
                }
            }
        },
        {
            "data": {
                "id": "duplicate-id",
                "type": "url",
                "attributes": {
                    "last_modification_date": 1800000000, # The NEW version of the duplicate
                    "positives": 99
                }
            }
        },
        {
            "data": {
                "id": None, # A record with no ID
                "type": "url",
                "attributes": {}
            }
        }
    ]
}

def test_deduplication_logic(api_data):
    """
    This function isolates and tests the de-duplication and reshaping logic.
    """
    print("--- Testing De-duplication Logic ---")
    
    unique_iocs = {}
    for item in api_data.get('iocs', []):
        ioc_data = item.get('data', {})
        ioc_id = ioc_data.get('id')
        
        if not ioc_id:
            print(f"Skipping record with no ID.")
            continue

        current_mod_date = ioc_data.get('attributes', {}).get('last_modification_date', 0)
        
        if ioc_id not in unique_iocs or current_mod_date > unique_iocs[ioc_id].get('attributes', {}).get('last_modification_date', 0):
            print(f"Accepting record for '{ioc_id}' with timestamp {current_mod_date}.")
            unique_iocs[ioc_id] = ioc_data
        else:
            print(f"Ignoring older record for '{ioc_id}' with timestamp {current_mod_date}.")

    # Reshape the final, de-duplicated data
    reshaped_iocs = []
    for ioc_id, data in unique_iocs.items():
        attributes = data.get('attributes', {})
        new_ioc = {
            "ioc_id": ioc_id,
            "ioc_type": data.get('type'),
            "last_modification_date": attributes.get('last_modification_date'),
            "positives": attributes.get('positives')
        }
        reshaped_iocs.append(new_ioc)
    
    final_ndjson = "\n".join(json.dumps(ioc) for ioc in reshaped_iocs)
    
    print("\n--- Final NDJSON Output ---")
    print(final_ndjson)
    
    # --- Verification ---
    assert 'unique-id-1' in final_ndjson, "Test Failed: Unique ID was dropped!"
    assert final_ndjson.count('duplicate-id') == 1, "Test Failed: Duplicates were not removed!"
    assert '"positives": 99' in final_ndjson, "Test Failed: The newest duplicate was not kept!"
    assert '"positives": 10' not in final_ndjson, "Test Failed: The older duplicate was kept!"
    
    print("\n✅ All tests passed!")

# Run the test
if __name__ == "__main__":
    test_deduplication_logic(MOCK_API_DATA)