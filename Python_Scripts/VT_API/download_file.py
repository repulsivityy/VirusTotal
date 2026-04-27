import requests
import os

def download_vt_file(api_key, file_id, output_filename):
    """
    Fetches the download URL for a file from VirusTotal and saves the file.
    
    Args:
        api_key (str): Your VirusTotal API key.
        file_id (str): The hash (SHA256, SHA1, or MD5) of the file to download.
        output_filename (str): The local path to save the downloaded file.

    The VirusTotal API for file downloads responds with a redirect to a temporary 
    download URL. The `requests` library is configured by default to automatically 
    follow this redirect, making the process straightforward.
    """
    
    api_url = f"https://www.virustotal.com/api/v3/files/{file_id}/download"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    print(f"Requesting download URL for file ID: {file_id}...")
    
    try:
        # Use a context manager to ensure the connection is closed.
        # `allow_redirects=True` is the default, so requests will handle the redirect.
        # `stream=True` is important for downloading files as it doesn't load
        # the entire content into memory at once.
        with requests.get(api_url, headers=headers, stream=True, timeout=60) as response:
            
            # This will raise an HTTPError if the HTTP request returned an unsuccessful status code.
            response.raise_for_status()

            # You can check if a redirect occurred by inspecting the response history.
            if response.history:
                print("Redirect was successfully followed.")
                print(f"Initial request URL: {response.history[0].url}")
                print(f"Final download URL: {response.url}")
            
            print(f"Downloading file and saving to '{output_filename}'...")
            
            # Write the content to the output file in chunks.
            with open(output_filename, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            print("\nDownload complete!")
            print(f"File saved at: {os.path.abspath(output_filename)}")

    except requests.exceptions.HTTPError as errh:
        print(f"Http Error: {errh}")
        # The error response from VirusTotal is often in JSON format.
        try:
            print(f"API Response: {errh.response.json()}")
        except ValueError:
            print(f"API Response: {errh.response.text}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")

# --- Main execution block ---
if __name__ == "__main__":
    # --- Configuration ---
    # IMPORTANT: Replace with your actual VirusTotal API key.
    # For better security, it's recommended to use an environment variable.
    # You can set it in your terminal like this:
    # export VT_API_KEY="your_real_api_key_here"
    VT_API_KEY = os.getenv("GTI_APIKEY")

    # The ID of the file you want to download (e.g., its SHA256 hash).
    TARGET_FILE_ID = input("Enter file hash: ").strip()
    
    # The desired name for the saved file.
    OUTPUT_FILENAME = f"{TARGET_FILE_ID}.downloaded"

    if VT_API_KEY == "<YOUR_API_KEY_HERE>":
        print("ERROR: Please replace '<YOUR_API_KEY_HERE>' with your actual API key,")
        print("or set it as an environment variable named 'VT_API_KEY'.")
    else:
        download_vt_file(VT_API_KEY, TARGET_FILE_ID, OUTPUT_FILENAME)