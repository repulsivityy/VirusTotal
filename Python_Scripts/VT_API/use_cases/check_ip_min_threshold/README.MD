This script analyzes IP addresses using VirusTotal and Shodan.io.

It categorizes IPs based on VirusTotal detections and fetches additional information for suspicious and malicious IPs.

## Requirements:
- VirusTotal API Key (set as environment variable VT_APIKEY)
- Shodan.io API Key (set as environment variable SHODAN_APIKEY)

## Usage:
1. Create a CSV file (e.g., `ips.csv`) with one IP address per line.
2. Run the script: `python GetIpAddr_minThreshold.py <path_to_your_ips.csv>` (e.g., `python GetIpAddr_minThreshold.py ips.csv`)
3. Enter the minimum detection threshold when prompted.

## Outputs:

### Malicious IPs
```
##################################
Detailed Report: Malicious IPs
##################################

69.49.230.198 - Shodan Info:
  Hostnames: ['1464509838.federalbusinesslegal.com', '69-49-230-198.webhostbox.net', 'www.1464509838.federalbusinesslegal.com', '69-49-230-198.cprapid.com']
  Ports: [2082, 995, 2086, 2087, 3306, 587, 110, 143, 80, 465, 2083, 53, 22, 443]
  OS: None
```

### Suspicious IPs
```
##################################
Detailed Report: Unknown IPs
##################################
194.58.111.54:
  Last known final URL: https://api.celfin.ru/auth (8 malicious detections)
  Referrer files: 10 (22 malicious detections)
  Link to VT graph: https://www.virustotal.com/graph/194.58.111.54
  Shodan Hostnames: ['194-58-111-54.cloudvps.regruhosting.ru', 'api.celfin.ru']
  Shodan Ports: [80, 3306, 443, 21, 22]
  Shodan OS: None
```