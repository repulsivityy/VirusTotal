# Threat Hunting Prompts

## SecOps Hunting

* Show me all failed login attempts from IP address
```
Show me all failed login attempts from IP addresses that have not previously authenticated successfully to this system within the past 30 days. Include the source IP, account name, and timestamp.
```

* Unusual traffic patterns
```
Identify unusual network traffic patterns, such as spikes in data transfer or connections to unfamiliar IP addresses in the past 30 days
```

* Suspicious Process Execution
```
Show me all processes launched from temp directories, user profile AppData in the last 7 days. Inlcude the process name, associated username, full commandline, and timestamp. Examine any suspicious behaviours - such as command line utilities - and enrich these indicators with gti. Provide the child processes should gti returns a verdict of suspicious or malicious. 
```

## Threat Intelligence
* Understanding Malware
```
Tell me more about Ransomhub Ransomware. Include their TTPs, threat actors observed to have used them, and any known IOCs first seen in the past 30 days. 
```

* Understanding Campaigns (Strategic) 
```
Based on this report <insert link>, summarise the report for a CISO. Include their TTPs
```

* Understanding Vulnerabilities
```
You are a cybersecurity analyst focusing on vulnerability management, and you are expected to update your CISO on the latest vulnerability trends. Focus on vulnerabilities actively exploited in the wild and those with a high potential for causing significant impact. Provide a summary of each vulnerability, its potential impact, and recommended mitigation strategies. Use key insights such as CISA Known Exploited Vulnerabilities (KEV) catalog, Common Vulnerability Scoring System (CVSS), as well as the Exploit Prediction Scoring System (EPSS).
```

* Understanding Campaigns + Hunting Packages (Operational / Tactical)
```
Based on this report <insert link>, summarise the report for a threat intelligence analyst. Please output the following: - any ttps/behaviours in the report - any indicators / iocs in the report in a table format. If there are any TTPs that we can use, convert them into a cyber threat hunting package based on YARA-L. Leverage Sysmon event data primarily when creating YARA-L rules
```

* Understanding campaigns for hypothesis
``` 
You are a threat hunter. Provide a list of hypotheses that we can test based on the following campaign report <insert link>. 
For each hypothesis, provide a list of data sources that we can use to test the hypothesis. 

<table_structure>
| Procedure | Description | Logs |
|-----------|-------------|------|
| Short title | Detailed description with patterns | Relevant logs and Event IDs |
</table_structure>

- Provide detailed technical information
- Structure the information according to the provided table structure format
- Include only actionable procedures for threat hunting
- Focus on specific search patterns
- Avoid generic or ambiguous information
- Include citations
```

* Understanding reports, and pulling IOCs and any rules
```
You are a threat hunter. Based on this report <insert link>, summarise the report for a threat intelligence analyst. Please output the following: 
  - any ttps/behaviours in the report 
  - any indicators / iocs in the report in a table format. 
If there are any rules such as YARA rules, automatically push them to my Livehunt rule on GTI 
```

* Ransomware Victims / Affliates Profile
```
Analyse Akira Ransomware Victims and Tactics.

# Follow up prompt if need be
Based on what was provided, provide some threat hunting hypotheses.
```


* Cyber Threat Actor Research Prompt
```
**Research Target:** [INSERT THREAT ACTOR NAME/APT GROUP]

## Research Objectives

Conduct comprehensive research on the specified threat actor to produce a detailed intelligence report covering their tactics, techniques, procedures, recent activities, and threat landscape implications.

## Required Research Areas

### 1. Threat Actor Profile & TTPs
- **Group Overview:** Official designations, aliases, suspected attribution
- **Tactics, Techniques & Procedures (TTPs):** Map to MITRE ATT&CK framework
- **Primary Tooling:** Custom malware, commodity tools, living-off-the-land techniques
- **Motivation & Objectives:** Financial gain, espionage, disruption, ideology, state-sponsored activities
- **Operational Characteristics:** Attack patterns, victim selection criteria, operational security practices

### 2. Recent Activities Analysis (Last 12 Months)
Create a table with the following columns for each significant incident:

| Date | Target/Victim | Attack Summary | Initial Access | Persistence | Execution | Financial Impact | Tools/Malware Used |
|------|---------------|----------------|----------------|-------------|-----------|------------------|-------------------|
| [Date] | [Organization/Sector] | [Brief description] | [MITRE Technique] | [MITRE Technique] | [MITRE Technique] | [$ Amount if known] | [Specific tools] |

**For each incident, provide:**
- Detailed attack timeline and methodology
- MITRE ATT&CK technique mappings for each phase
- Specific malware families or tools employed
- Data exfiltration methods and scope
- Estimated financial damages or losses
- Attribution confidence level

### 3. Technical Indicators & Artifacts
- **Indicators of Compromise (IoCs):**
  - File hashes (MD5, SHA-1, SHA-256)
  - IP addresses and domains
  - Registry keys and file paths
  - Network signatures
  - Email indicators
- **Malware Analysis:**
  - Malware family names and variants
  - Command and control infrastructure
  - Persistence mechanisms
  - Evasion techniques
- **Infrastructure Analysis:**
  - Hosting providers and registrars
  - Domain registration patterns
  - Infrastructure reuse patterns

### 4. Targeting Patterns & Victimology
- **Geographic Distribution:** Countries and regions targeted
- **Sector Analysis:** Industries and organization types
- **Victim Characteristics:** Common attributes of targeted entities
- **Timeline Analysis:** Evolution of targeting over time

### 5. Threat Assessment & Predictions
- **Current Threat Level:** Assessment of ongoing activity
- **Future Targeting Predictions:** 
  - Likely next targets (sectors/regions)
  - Emerging attack vectors
  - Potential escalation scenarios
  - **Disclaimer:** *These predictions are based on available intelligence and historical patterns. Actual threat actor behavior may vary, and assessments should be considered analytical judgments rather than definitive forecasts.*

### 6. Defensive Recommendations
Provide 3-5 actionable recommendations:
1. **Detection & Monitoring:** Specific indicators to monitor
2. **Prevention Controls:** Technical and procedural safeguards
3. **Incident Response:** Preparation strategies for potential attacks
4. **Threat Hunting:** Proactive search strategies
5. **Intelligence Sharing:** Relevant information sharing initiatives

## Research Sources
- Open source intelligence (OSINT)
- Threat intelligence platforms
- Security vendor reports
- Government advisories
- Academic research
- Industry incident reports

## Deliverable Format
- Executive summary (1-2 pages)
- Detailed technical analysis
- Visual timeline of recent activities
- IoC appendix with machine-readable formats
- Reference list with source credibility assessment

## Quality Standards
- Verify information across multiple sources
- Distinguish between confirmed facts and analytical assessments
- Provide confidence levels for key judgments
- Include source attribution and publication dates
- Highlight any information gaps or limitations
```

## Vulnerabilities

* Understanding specific vulnerabilities

```
Tell me about the log4j vulnerability. Include the CVE number, CVSS score, and a summary of the vulnerability. Provide recommendations on what I need to do to remediate this vulnerability. Check if I have any open cases or if my scc shows any alerts related to it
```

```
Tell me about the cve-2025-31324 vulnerability. Include the CVE number, CVSS score, and a summary of the vulnerability. Explain in point form, who has been observed exploiting this vulnerability, why this vulnerability is critical, and the risk associated with it. 
  - Provide recommendations on what I need to do to remediate this vulnerability. 
  - Check if I have any open cases or alerts based on the file hashes in the report. 
  - Structure the response for a CISO
```

