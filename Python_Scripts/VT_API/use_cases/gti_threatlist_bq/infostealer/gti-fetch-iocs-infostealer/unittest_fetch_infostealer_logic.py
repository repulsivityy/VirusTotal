import json
import unittest
from unittest.mock import patch, MagicMock

# Import the function we want to test from the main script
from main import fetch_and_store_gti_data

# This class simulates the response from the 'requests' library
class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP Error {self.status_code}")

# This is the mock data for our test, simulating a "dirty" API response
MOCK_API_DATA = {
    "iocs": [
        {
            "data": {
                "id": "unique-id-1",
                "type": "file",
                "attributes": { "last_modification_date": 1700000000, "md5": "abc" }
            }
        },
        {
            "data": {
                "id": "duplicate-id",
                "type": "file",
                "attributes": { "last_modification_date": 1600000000, "md5": "old_md5" }
            }
        },
        {
            "data": {
                "id": "duplicate-id",
                "type": "file",
                "attributes": { "last_modification_date": 1800000000, "md5": "newest_md5" }
            }
        }
    ]
}

class TestFetchLogic(unittest.TestCase):

    @patch('main.gcs_upload')
    @patch('main.get_gti_api_key')
    @patch('main.requests.get')
    @patch.dict('os.environ', {
        "GCP_PROJECT": "test-project",
        "BUCKET_NAME": "test-bucket",
        "SECRET_NAME": "test-secret"
    })
    def test_deduplication_and_reshaping(self, mock_requests_get, mock_get_key, mock_gcs_upload):
        """
        Tests that the fetch function correctly de-duplicates and reshapes the data.
        """
        print("\n--- Testing Infostealer Fetch Logic ---")

        # Configure the mock responses
        mock_get_key.return_value = "fake-api-key"
        mock_requests_get.return_value = MockResponse(MOCK_API_DATA, 200)

        # Call the actual Cloud Function
        fetch_and_store_gti_data(request=None)

        # Assert that gcs_upload was called exactly once
        mock_gcs_upload.assert_called_once()
        
        # Get the NDJSON data that was passed to the upload function
        ndjson_output = mock_gcs_upload.call_args[0][2]

        print("\n--- Final NDJSON Sent to GCS ---")
        print(ndjson_output)

        # Verification asserts
        self.assertIn('unique-id-1', ndjson_output, "Test Failed: Unique ID was dropped!")
        self.assertEqual(ndjson_output.count('duplicate-id'), 1, "Test Failed: Duplicates were not removed!")
        self.assertIn('newest_md5', ndjson_output, "Test Failed: The newest duplicate was not kept!")
        self.assertNotIn('old_md5', ndjson_output, "Test Failed: The older duplicate was kept!")
        
        print("\n✅ All tests passed!")


if __name__ == '__main__':
    unittest.main()