# MAVE - Mandiant Advantage Vulnerability Explorer

## 1. About this script
This python3 script was purpose built to read a file from the command line, regex the CVE-IDs from that file, and present the unique set of CVE-ID's to the Mandiant Advantage APIv4 to find matches.  If there are CVE-ID matches,  the results will be populated into a html output file which can be rendered locally.  The result will aid customers with prioritization as the primary chart is built using the exploitRating and riskRating API output fields.  So that customers can easily see that of the vulnerabilities they have, which pose the most threats.  

Change details (v1.22)
  - bugfix: solved an issue to re-use session connections
  - feature: added support for rating_types filter for predicted, analyst, and unrated.
  - feature: updated the script processing limit to 50k CVE-IDs

Change details (v1.19)
  - bugfix: resolved an issue where a special character in the response CVE-ID title wont render correctly in the html.
  - feature: added the CVE-IDs that have no API response into the log file (unenriched CVE-IDs)

Change details (v1.15):
  - feature: support for the March 30th, 2023 enhanced vulnerability intelligence update 
  - bugfix: Updated issue with null title to correctly render final html
  - bugfix: Updated API call to v4 for "limit":100 when calling > 50 cveIDs for enrichment
  - feature: case insensitive regex search of cveIDs enabled
  - feature: added Exploitation Vectors and Was Zero Day to output
  - feature: removed anticipated as a field from the chart for exploitRating
  - feature: selectable show/hide columns (max 10 at a time)
    
As a feature of the [Enhanced Vulnerability Intelligence Offering](https://mandiant.com/resources/blog/enhanced-vulnerability-intelligence), released on March 30th, 2023,  our Mandiant Advantage APIv4 now contains intel analyst scored CVE-IDs and non intel analyst scored CVE-IDs.

  - non intel analyst scored CVE-IDs will be rendered as part of the MAVE output. 
    - exploitRating and riskRating will **NOT** be populated 
    - hyperlinks to the Mandiant Advantage portal will be populated in the html outputs
    - additional meta-data rendered as available in both the html and the csv outputs

  - analyst scored CVE-IDs will work as expected
    - exploitRating and riskRating values will be populated
    - additional meta-data such as associated actors and malware will be populated

**NOTE**: Please review the LICENSE.txt file before using this script for the first time.

## 2. Requirements
This python script requires the requests, argparse and jinja2 libraries, typically installed in python3 by doing a pip install -r requirements.txt.

## 3. Running the script
Before attempting to run the script,  the user should update the keys.py file with their Mandiant Advantage v4 API keys.  APIv4 public and secret authentication keys can be downloaded from https://advantage.mandiant.com, logging in, then going to settings near the search box, and then under account management. Click on API Access and Keys on bottom left, and then on Get Key ID and Secret.

Once your API keys are set up in the keys.py file,  you should be able to successfully run the script.

The python3 script MAVE_lite.py takes a couple of arguments, see the usage statement below:

**usage:** *MAVE_lite.py [-h] [-i INPUT_FILE] [-csv CSV_OUTPUT_FLAG] [-p PROXY_PASS] [-th  MAX_THREAD]* 

optional arguments:
  -h, --help            show this help message and exit
  -i   INPUT_FILE       REQUIRED: File name with extension to read as an input
  -csv CSV_OUTPUT_FLAG  OPTIONAL: A flag 'y' or 'n' showing if a csv output is required, default is 'n'
  -p   PROXY_PASS       OPTIONAL: Authentication password for proxy connection, default is 'no_pass'
  -th  MAX_THREAD       OPTIONAL: Number of max_threads that we want the system to spawn, default and maximum value allowed is '250'  

A Typical run would be:  **C:\MAVE>python3 MAVE_lite.py -i <file_name>**

During execution the user will see the progress of the API calls in the form of percentage of found cve's to API calls made.  For very small files, this will not take very long, for larger files, the output will show how many calls have been made and percentage completed.

Once done, if the script has finished successfully,  the user will see the following:

Execution completed, please check the output file *output\file_name.html*

## 4. Setting proxy server
If there is a need to route the requests to our APIs through a proxy server,  please open the file proxy_config.py and mark the property ENABLE_PROXY to 'y'.
If the proxy server needs authentication, please update the property NEED_PASS to 'y' and update the property PROXY_USR and PROXY_PASS with username and password to proxy respectively. 


## 5. Viewing the output
Please navigate to the dropped folder "output" to look for an ".html" file that would be "<file_name>.html", the file_name will be the original name of the file that was the input, and that name was used to name the output html file.

### * *User Interaction field and CVSSv3 Base / Temporal fields*
Some CVE-IDs do not have the **User Interaction** nor the **CVSS v3 Base and Temporal fields** populated in our data set,  therefore when the final output is viewed those CVE-IDs will have blanks in the final html,  this is expected and not a bug in the API or scripting.

## 6. Problems
If your output html file is of zero length,  or there are issues with the API output, please navigate to the logs folder and review the log from the "run" that you performed to obtain some information about the "run".

## 7. Feedback
Please send feedback to mandiant-intel-tech-accelerations [at] google.com, subject: MAVE.
