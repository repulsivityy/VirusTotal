import os
import unittest
from unittest.mock import patch, MagicMock

# Set mock environment variables for the infostealer pipeline
os.environ["GCP_PROJECT"] = "test-project"
os.environ["BQ_DATASET_NAME"] = "test-dataset"
os.environ["BQ_TABLE_NAME"] = "infostealer"
os.environ["BQ_STAGING_TABLE_NAME"] = "infostealer_staging"

import main

class TestMergeLogic(unittest.TestCase):

    @patch('main.bigquery.Client')
    def test_merge_sql_is_correct(self, mock_biquery_client):
        """
        Tests that the generated MERGE SQL statement is correct for the infostealer table.
        """
        print("--- Testing Infostealer MERGE SQL statement generation ---")
        
        mock_instance = MagicMock()
        mock_biquery_client.return_value = mock_instance

        main.execute_bigquery_merge(request=None)

        mock_instance.query.assert_called_once()
        
        actual_sql = mock_instance.query.call_args[0][0]
        
        print("\n--- Generated SQL ---")
        print(actual_sql)

        # Assertions to verify the SQL is correct for the infostealer tables
        self.assertIn("MERGE `test-project.test-dataset.infostealer` T", actual_sql)
        self.assertIn("USING `test-project.test-dataset.infostealer_staging` S", actual_sql)
        self.assertIn("ON T.ioc_id = S.ioc_id", actual_sql)
        self.assertIn("T.md5 = COALESCE(S.md5, T.md5)", actual_sql) # Check a field specific to this schema
        
        print("\n✅ SQL structure for infostealer is correct!")

if __name__ == '__main__':
    unittest.main()