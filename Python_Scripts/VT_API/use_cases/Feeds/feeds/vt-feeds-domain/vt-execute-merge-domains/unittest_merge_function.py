import unittest
from unittest.mock import patch, MagicMock, call
import os

# Import the function from 'main.py'
from main import execute_bigquery_merge

class TestMergeFunction(unittest.TestCase):

    @patch.dict(os.environ, {
        "GCP_PROJECT": "test-project-merge",
        "BQ_DATASET_NAME": "test_dataset_merge",
        "BQ_TABLE_NAME": "final_domains",
        "BQ_STAGING_TABLE_NAME": "staging_domains"
    })
    @patch('main.bigquery.Client')
    def test_merge_handles_duplicates_in_staging(self, mock_bigquery_client):
        """
        Tests that the generated SQL correctly de-duplicates the source data.
        """
        # 1. Setup
        mock_request = MagicMock()
        mock_job = MagicMock()
        mock_job.dml_stats.inserted_row_count = 10
        mock_job.dml_stats.updated_row_count = 5
        mock_bigquery_client.return_value.query.return_value = mock_job

        # 2. Execution
        execute_bigquery_merge(mock_request)

        # 3. Assertions
        instance = mock_bigquery_client.return_value
        self.assertEqual(instance.query.call_count, 2)
        
        merge_sql = instance.query.call_args_list[0].args[0]
        truncate_sql = instance.query.call_args_list[1].args[0]

        # FIX: Check for 'PARTITION BY id' instead of 'ioc_id'
        self.assertIn("PARTITION BY id", merge_sql)
        
        # Assert that it orders by the latest analysis date.
        self.assertIn("ORDER BY attributes.last_analysis_date DESC", merge_sql)
        
        # Assert that the rest of the query is still correct
        self.assertIn("MERGE `test-project-merge.test_dataset_merge.final_domains`", merge_sql)
        self.assertIn("TRUNCATE TABLE `test-project-merge.test_dataset_merge.staging_domains`", truncate_sql)
        
        print("\n✅ test_merge_handles_duplicates_in_staging passed.")


if __name__ == '__main__':
    unittest.main()