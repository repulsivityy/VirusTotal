import unittest
from unittest.mock import patch, MagicMock
import os

# FIX: Import the function from 'main.py' where your cloud function code resides.
from main import gcs_to_bigquery_loader

class TestLoadFunction(unittest.TestCase):

    @patch.dict(os.environ, {
        "GCP_PROJECT": "test-project",
        "BQ_DATASET_NAME": "test_dataset",
        "BQ_STAGING_TABLE_NAME": "test_staging_table"
    })
    @patch('main.bigquery.Client') # Also patch the client where it's used: in 'main'
    def test_gcs_to_bigquery_loader(self, mock_bigquery_client):
        """
        Tests that the load function is called with the correct parameters and job config.
        """
        # 1. Setup
        mock_event = {
            'bucket': 'test-bucket',
            'name': 'domain-feeds/202507051030.jsonl'
        }
        mock_context = MagicMock()

        # 2. Execution
        gcs_to_bigquery_loader(mock_event, mock_context)

        # 3. Assertions
        mock_bigquery_client.assert_called_once()
        instance = mock_bigquery_client.return_value
        call_args, call_kwargs = instance.load_table_from_uri.call_args
        
        expected_uri = "gs://test-bucket/domain-feeds/202507051030.jsonl"
        self.assertEqual(call_args[0], expected_uri)

        job_config = call_kwargs['job_config']
        self.assertEqual(job_config.write_disposition, 'WRITE_APPEND')
        
        instance.load_table_from_uri.return_value.result.assert_called_once()
        print("\n✅ test_gcs_to_bigquery_loader passed.")


if __name__ == '__main__':
    unittest.main()