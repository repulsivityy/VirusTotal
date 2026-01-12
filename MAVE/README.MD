# Mandiant Advantage Vulnerability Explorer (MAVE) Integration
Developed By: 	Mandiant
Latest Version: 	1.22
Last Released: 	August 2023
Key Contact: 	Support
Download: 	MAVE-lite.v1.22.zip (md5: 487b8f4d23584210a26a433843b82db8)

### MAVE Technical Acceleration
Mandiant Advantage Vulnerability Explorer (MAVE) is a proprietary python3 script that lets you interact directly with the Mandiant Advantage Threat Intelligence (MATI) API. You can correlate your Common Vulnerability & Exposures IDs (CVE-IDs) against the vulnerability intelligence it provides.

MAVE is considered a Technical Acceleration capability for customer use. It provides an example script to demonstrate features or example code of how to perform a task with the MATI API. With the distributed license, the Mandiant team that built this product will provide support and update as time permits. 

### MAVE background
MAVE was primarily built for customers to easily query multiple vulnerabilities at the same time, and to review those results as a “set” of information. MAVE supports the common use case for analysts seeking quick, ad hoc answers from the MATI API regarding the results of an internal vulnerability scan, for example.

MAVE is a python3 script built to do the following:

Read a file from the command line
Extract the CVE-IDs from the file into a unique set
Query the MATI API for additional metadata on each vulnerability

### MAVE outputs
If the API has CVE-ID matches, the results of the matches are populated into an HTML output file. You can optionally export the results into a CSV file for parsing and sorting larger datasets.

The HTML output file helps you prioritize your mitigation efforts by categorizing each vulnerability based on its Exploitation State (y-axis) and Risk Rating (x-axis). An intuitive chart that shows the number of vulnerabilities from the list that fall into each possible combination of these factors. Best practice is to focus first on vulnerabilities that have the highest values for both Exploit Rating and Risk Rating.

Up to ten columns can be displayed in the HTML output file. Columns can be added or removed as desired by selecting them from the Showing columns list.

Hyperlinks in the HTML output file let you quickly pivot to explore each vulnerability, associated threat actors, or malware families directly within the MATI platform.

### Usage
1. Enter your MATI API Public and Secret Keys in the keys.py file. 
>For GTI users, use "gti-user" as the public key, and your API key as the secret key

2. python3 MAVE_lite.py -i <file_name>



