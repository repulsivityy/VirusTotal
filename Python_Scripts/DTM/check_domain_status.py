import csv
import requests
import tkinter as tk
from tkinter import filedialog
from urllib.parse import urlparse

def select_file():
    root = tk.Tk()
    root.withdraw()  # Hide the main tkinter window
    file_path = filedialog.askopenfilename(
        title="Select your CSV file",
        filetypes=[("CSV files", "*.csv")]
    )
    return file_path

def check_domains():
    input_file = select_file()
    
    if not input_file:
        print("No file selected. Exiting.")
        return

    output_file = input_file.replace('.csv', '_results.csv')
    results = []

    try:
        with open(input_file, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            
            # Identify the column name (handling potential spaces/BOM)
            headers = reader.fieldnames
            domain_col = headers[0] # Assumes 'domains' is the first column

            for row in reader:
                original_input = row[domain_col].strip()
                if not original_input:
                    continue

                # --- Logic to handle mixed Domains and URLs ---
                parsed = urlparse(original_input)
                # If scheme is missing (e.g., 'google.com'), add 'http://'
                url = original_input if parsed.scheme else f"http://{original_input}"
                
                print(f"Checking: {url}")
                
                try:
                    # We use allow_redirects=True to get the final status code
                    response = requests.get(url, timeout=10, allow_redirects=True)
                    status = "alive"
                    code = response.status_code
                except requests.RequestException:
                    status = "dead"
                    code = "N/A"
                
                results.append({
                    'domains': original_input,
                    'ping status': status,
                    'http response': code
                })

        # Save to new file
        keys = ['domains', 'ping status', 'http response']
        with open(output_file, mode='w', newline='', encoding='utf-8') as outputcsv:
            writer = csv.DictWriter(outputcsv, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
            
        print(f"\n--- Process Complete ---")
        print(f"Results saved to: {output_file}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    check_domains()