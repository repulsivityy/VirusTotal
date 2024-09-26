# VirusTotal Intelligence Dork (vt-dork)

## Introduction

VirusTotal Intelligence (VTI) allows one to search through VirusTotal's entire dataset accordingly to many different variables, from binary properties, antivirus detection verdicts, behaviour patterns such as outgoing communication, and more. 
VTI provides powerful search capabilities with mulitple search modiferes to search across the different data corpus of Files, Domains, IP Address, URLs. <br>

All search terms is structured as ***modifier:value***.
The image below from VirusTotal's blog provides the basis of how information is structured. 

<p align="center">
  <img src="https://lh7-rt.googleusercontent.com/docsz/AD_4nXdJ1cLcETZLA8AQG4szbnYyDQdEk3zn9PTtfcf7pwun5Kf-pAhYxQPH5Rf02WL8rxGBklRa7uyCo04VctDMuGTeku6k_yLvna6MiDfpsyuUEveCg50ppeUzElUz4ZWSLR6l6p6uvrzRVR3aezkSAiDDNFU?key=fmyi2KLpW11xkeIveMXX7Q" width="800" alt="VirusTotal Dataset Structure"> <br>
<a href="https://blog.virustotal.com/2024/08/VT-S1-EffectiveResearch.html">Exploring the VirusTotal Dataset</a>
</p>

This document will list searches that are relevant for threat hunting on VT. 

## General Searches

Searching for files with at least 10 detections
```
entity:file p:10+
```

Searching for files with at least 10 detections that have been detected as ransomware
_modifier engines is use for malware family names, types of malwares (eg, info-stealers, trojans, etc), or malware categories_
```
entity:file p:10+ engines:ransom
```

Searching for any filenames starting the string mimi <br>
_(the "entity:file" modifer is not required as the modifier "name" implies searching through the File corpus, but is included for clarity and consistency sake)_

```
entity:file name:mimi* 
```

Searching for pe files submitted to VT with 20 detections, submitted in Singapore
```
entity:file type:pe p:20+ submitter:sg
```

Searching for excel files between 1-5 detections that have macros
```
entity:file type:excel p:1+ p:5- tag:macros
```

Searching for files weaponised that exploits any vulnerability in 2024 last seen in the past 14 days
```
tag:cve-2024-* ls:14d+ 
```

## Hunting for files with network indicators

Files hosted on a .gov with at least 5 detections
```
itw:"*.gov" p:5+
```

Files communicating with time.microsoft.com
```
behaviour:"time.microsoft.com"
```

Files communicating with time.microsoft.com (alternative method that's more precise)
```
behaviour_network:"time.microsoft.com"
```

## Hunting with Content Searches 

Files with specific strings: 
```
content:"UploadSmallFileWithStopWatch"
```

Content / Binary Seaches
```
content:"{ 46 69 6C 65 43 6F 6E 74 61 69 6E 65 72 2E 46 69 6C 65 41 72 63 68 69 76 65 }"
```

## Brand / Domain Monitoring

Searching for any URLs that have been categorised or detected as phishing
```
entity:url (engines:phishing or category:phishing)
```

Searching for typo-squatting domains (leverging fuzzy searches) that looks like Googles but not from the legitimate Google domain
```
entity:domain fuzzy_domain:google.com NOT parent_domain:google.com
```
