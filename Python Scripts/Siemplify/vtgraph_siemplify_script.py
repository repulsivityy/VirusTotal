from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT
import requests

@output_handler
def main():
    siemplify = SiemplifyAction()
    hash_to_get_graphs_for = siemplify.extract_action_param("Hash", print_value=True)
    hash_to_get_graphs_for = hash_to_get_graphs_for.split(",") # this split a comma-separated stting into list of values
    
    status = EXECUTION_STATE_COMPLETED  # used to flag back to siemplify system, the action final status
    output_message = "Found information about the hash from VT"  # human readable message, showed in UI as the action result
    result_value = True  # Set a simple result value, used for playbook if\else and placeholders.
    
    json_result = {}
        try:
            for hash1 in hash_to_get_graphs_for:
                url = f"https://www.virustotal.com/api/v3/graphs?filter={hash1}"
                headers = {"x-apikey": "XXXXXXXXXKEYXXXXXXKEY"}
                response = requests.get(url, headers=headers)
                json_result[hash1] = response.json().get("data")
                
                except Exception as e:
                output_message = "Error"  # human readable message, showed in UI as the action result
                result_value = False  # Set a simple result value, used for playbook if\else and placeholders.
                
                siemplify.result.add_result_json(json_result)
                
                siemplify.LOGGER.info("\n status: {}\n result_value: {}\n output_message: {}".format(status,result_value, output_message)) siemplify.end(output_message, result_value, status)
                
                if __name__ == "__main__":
                    main()
                    