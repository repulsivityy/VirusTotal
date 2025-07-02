import os
import unittest
from unittest.mock import patch, MagicMock

# Set mock environment variables before importing main
os.environ["GCP_PROJECT"] = "test-project"
os.environ["BQ_DATASET_NAME"] = "test-dataset"

import main

class TestMergeLogic(unittest.TestCase):

    @patch('main.bigquery.Client')
    def test_merge_sql_is_correct(self, mock_biquery_client):
        """
        Tests that the generated MERGE SQL statement is correct.
        """
        print("--- Testing MERGE SQL statement generation ---")
        
        # Create a mock instance of the BigQuery client
        mock_instance = MagicMock()
        mock_biquery_client.return_value = mock_instance

        # Call the function. It will use our mock client instead of the real one.
        main.execute_bigquery_merge(request=None)

        # Assert that the client's query method was called exactly once
        mock_instance.query.assert_called_once()
        
        # Get the actual SQL query that was passed to the method
        actual_sql = mock_instance.query.call_args[0][0]
        
        print("\n--- Generated SQL ---")
        print(actual_sql)

        # --- Assertions to verify the SQL is correct ---
        self.assertIn("MERGE `test-project.test-dataset.malicious_urls` T", actual_sql)
        self.assertIn("USING `test-project.test-dataset.malicious_urls_staging` S", actual_sql)
        self.assertIn("ON T.ioc_id = S.ioc_id", actual_sql)
        self.assertIn("WHEN MATCHED THEN", actual_sql)
        self.assertIn("WHEN NOT MATCHED THEN", actual_sql)
        self.assertIn("T.positives = COALESCE(S.positives, T.positives)", actual_sql)
        
        print("\n✅ SQL structure is correct!")

# This allows you to run the test directly
if __name__ == '__main__':
    unittest.main()