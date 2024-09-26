# VirusTotal Intelligence Dork (vt-dork)

## Introduction

VirusTotal Intelligence (VTI) allows one to search through VirusTotal's entire dataset accordingly to many different variables, from binary properties, antivirus detection verdicts, behaviour patterns such as outgoing communication, and more. 
VTI provides powerful search capabilities with mulitple search modiferes to search across the different data corpus of Files, Domains, IP Address, URLs. <br>

This image from VirusTotal's blog provides the basis of how information is structured. 

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
```
entity:file p:10+ engines:ransom
```

Searching for any files starting with the string mimi
(the modifer "entity:file" is not required as the modifier "name" implies searching through the File corpus, but included for clarity and consistency sake)

```
entity:file name:mimi* 
```