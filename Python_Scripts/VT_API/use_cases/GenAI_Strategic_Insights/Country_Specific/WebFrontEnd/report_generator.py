# report_generator.py

import os
import re
import asyncio
import datetime
from tqdm import tqdm
import aiohttp
import json
from dotenv import load_dotenv

# ==============================================================================
#  Configuration and Initialization
# ==============================================================================

def load_env_vars(gti_key_ui=None, gemini_key_ui=None):
    """
    Loads API keys, prioritizing keys from the UI, then falling back to .env file.
    """
    load_dotenv()
    
    gti_api_key = gti_key_ui if gti_key_ui else os.getenv("GTI_APIKEY")
    gemini_api_key = gemini_key_ui if gemini_key_ui else os.getenv("GEMINI_APIKEY")
    
    if not gti_api_key:
        raise ValueError("GTI API Key is missing. Provide it in the UI or in the .env file.")
    if not gemini_api_key:
        raise ValueError("Gemini API Key is missing. Provide it in the UI or in the .env file.")
        
    return gti_api_key, gemini_api_key

# ==============================================================================
#  Helper Functions (from original script, largely unchanged)
# ==============================================================================

def parse_report_from_api(report_data):
    """Parses a single report from the GTI API response."""
    attrs = report_data.get('attributes', {})
    creation_timestamp = attrs.get('creation_date')
    creation_date_str = datetime.datetime.fromtimestamp(creation_timestamp).isoformat() if creation_timestamp else ''
    report_id = report_data.get('id', '')

    # Construct the user-friendly GUI link instead of using the API self-link
    gui_link = f"https://www.virustotal.com/gui/collection/{report_id}" if report_id else ""

    return {
        'report_id': report_id,
        'name': attrs.get('name', ''),
        'link': gui_link,
        'content': attrs.get('content', '')
    }

def extract_cves_from_text(text):
    """Extracts unique CVE identifiers from a block of text."""
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    return set(cve_pattern.findall(text))

def parse_vulnerability_from_api(cve_id, vuln_data):
    """Parses vulnerability details from the GTI API response."""
    try:
        attributes = vuln_data.get('data', {}).get('attributes', {})
        cvss_data = attributes.get('cvss', {})
        cwe_data = attributes.get('cwe', {})
        cisa_kev_data = attributes.get('cisa_known_exploited', {})
        is_in_kev = "Yes" if cisa_kev_data and cisa_kev_data.get('added_date') else "No"
        return {
            "cve_id": cve_id.upper(),
            "name": attributes.get('name', cve_id.upper()),
            "risk_rating": attributes.get('risk_rating', 'N/A'),
            "cwe_title": cwe_data.get('title', 'N/A'),
            "cvss_v4_score": cvss_data.get('cvssv4_x', {}).get('score', 'N/A'),
            "cisa_kev": is_in_kev,
        }
    except (KeyError, TypeError):
        return None

async def fetch_vulnerability_details(session, gti_api_key, cves):
    """Fetches details for a set of CVEs from the GTI API."""
    headers = {'x-apikey': gti_api_key, 'x-tool': 'WebAppGTI'}
    async def fetch_single_cve(cve_id):
        url = f"https://www.virustotal.com/api/v3/collections/vulnerability--{cve_id.lower()}"
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return parse_vulnerability_from_api(cve_id, await response.json())
                return None
        except Exception as e:
            print(f"Error fetching CVE {cve_id}: {e}")
            return None

    tasks = [fetch_single_cve(cve) for cve in cves]
    results = [result for result in await asyncio.gather(*tasks) if result]
    return results

async def fetch_reports(session, gti_api_key, country, source, start_date='5d', limit=450):
    """Fetches intelligence reports from the GTI API."""
    print(f"Fetching reports for {country} (Source: {source})...")
    base_url = 'https://www.virustotal.com/api/v3/collections'
    headers = {'x-apikey': gti_api_key, 'x-tool': 'WebAppGTI'}

    # Dynamically build the filter string based on the source selection
    base_filter = f"collection_type:report target_country:{country} creation_date:{start_date}+"
    
    origin_filter = ""
    if source == "crowdsource":
        origin_filter = " NOT origin:'Google Threat Intelligence'"
    elif source == "gti":
        origin_filter = " origin:'Google Threat Intelligence'"
    # If source is 'both', the origin_filter remains empty.

    full_filter = base_filter + origin_filter

    params = {
        "filter": full_filter,
        "order": "creation_date-", "limit": 40
    }
    collections, next_url = [], base_url
    
    # Using a simple loop as tqdm is not ideal for a web UI backend
    while next_url and len(collections) < limit:
        async with session.get(next_url, headers=headers, params=params) as response:
            if params: params = None
            response.raise_for_status()
            data = await response.json()
            fetched_data = data.get('data', [])
            parsed = [parse_report_from_api(item) for item in fetched_data]
            collections.extend(parsed[:min(len(parsed), limit - len(collections))])
            next_url = data.get('links', {}).get('next') if len(collections) < limit else None
    
    print(f"✅ Fetched {len(collections)} reports.")
    return collections

def get_system_instruction(output_country, output_language):
    """Creates the detailed system instruction prompt for the Gemini model."""
    return f"""
    <PROMPT>
        <ROLE>
            You are a highly sophisticated AI simulating a skilled writer with the combined expertise of a **seasoned Threat Intelligence Analyst** and an **Editor-in-Chief**. You have a keen ability to identify and summarize threat landscape developments with specific relevance to a particular country and communicate them clearly in the local language. Your writing is authoritative, concise, accurate, and engaging.
        </ROLE>

        <TASK>
            Generate a **compelling, concise, and engaging weekly threat intelligence newsletter** focused on the most important landscape developments relevant to the specified {output_country}. You must filter provided reports for relevance, select the top stories, and summarize them accurately in {output_language}. The output format must be followed precisely.
        </TASK>

        <CONTEXT>
            This newsletter serves as a key intelligence touchpoint for customers and security professionals operating in the {output_country}. It offers a curated, easy-to-digest summary of the most critical developments impacting their security posture. The goal is to provide actionable or contextually significant intelligence tailored to their specific region.
        </CONTEXT>

        <INPUT_FORMAT>
            1.  **`TARGET_COUNTRY`:** The specific country the newsletter should focus on (e.g., "Brazil," "Germany," "Japan").
            2.  **`TARGET_LANGUAGE`:** The language for the final output (e.g., "Portuguese," "German," "Japanese").
            3.  **`REPORT_OBJECTS`:** A list of intelligence report objects, primarily with `Origin` of 'Crowdsourced' or 'Partner', but may also include 'News Analysis' reports for perspective. Each object may contain fields such as:
                * `content`: Text of the report/summary.
                * `link`: URL to the source.
                * `report_id` (for any `origin:Google Threat Intelligence` reports).
                * `date`: Publication or update date.
        </INPUT_FORMAT>

        <PROCESSING_INSTRUCTIONS>
           1.  **Read & Filter for Country Relevance:**
            * Analyze all provided `REPORT_OBJECTS`.
            * Create a shortlist of reports that have **direct relevance** to organizations, government entities, or individuals in {output_country}. This includes threats originating from, targeting, or having specific industry or geopolitical implications for that country.

        2.  **Select & Synthesize for the Newsletter:**
            * From your country-relevant shortlist, select the **top 8-10 most significant stories**, such as:
                * Active, widespread exploitation of a vulnerability or cyber attacks affecting organizations in `{output_country}`.
                * Confirmed major intrusion against a critical infrastructure entity or major corporation in `{output_country}`.
                * A new campaign by a threat actor known to target `{output_country}` or its key industries.
                * A globally significant threat with high potential impact on `{output_country}`.
                * Geopolitical developments or shifts in the regional threat landscape, including regional instabaility, disinformation campaigns and influence operations.
            * If the same topic is covered in multiple reports, synthesize the information into a single summary item.
            * For each selected story, write a concise summary (2-4 sentences).
            * **Include CVEs in Headlines:** If a story revolves around a specific vulnerability or vulnerabilities, ensure the CVE identifier (e.g., CVE-2024-12345) is mentioned prominently in the bold title or the first sentence of the summary. This is critical for the vulnerability enrichment step that happens *after* you generate the text.
            * **Link Source:** Ensure each summary includes an inline link to the primary OSINT source report using its `link` field. Prioritize media sources based in the same region as the {output_country}.

        3.  **Group and Structure the Output:**
            * After synthesizing the summaries, group them into logical thematic sections. Common sections could include:
                * `**Active Exploitation & Critical Vulnerabilities**` (for items with CVEs being actively exploited).
                * `**Threat Actor Activity & Campaigns**` (for news about specific APTs or cybercrime groups targeting the country).
                * `**Malware & Phishing Trends**` (for notable malware or social engineering campaigns).
                * `**Geopolitical & Industry-Specific Threats**` (for broader context items).
            * Do not create a section if there are no relevant items for it. The total number of items should still be between 7-10.

        4.  **Translate to Target Language:**
            * Ensure the entire final output, including all headings and summaries, is written fluently and accurately in {output_language}.
        </PROCESSING_INSTRUCTIONS>

        <OUTPUT_FORMAT>
            Generate the briefing in Markdown, adhering strictly to the following structure and translating all static text (headings, greetings) into the **`TARGET_LANGUAGE`**.

            1.  **Date:** Start with the full date (e.g., `Tuesday, April 15, 2025`).
            2.  **Title:** Add a bold title on the next line: `**Google Threat Intelligence Update for {output_language}**` (Translated).
            3.  **Greeting:** Add a simple, professional greeting (Translated).
            4.  **Summary Paragraph:** Write a brief (2-4 sentence) introductory paragraph highlighting the 1-2 most important developments covered below, based *only* on selected items. If a broader trend or connection between multiple items was identified, mention it here.
            5.  **Section:** Include a single main section, for example: `**Key Threat Landscape Developments**` (Translated).
            6.  **List Items:** Within the main section, list the 8-10 individual story summaries using Markdown bullet points (`* `).
                * Start each item with a bold title/phrase summarizing the story (Translated).
                * Provide a concise (2-4 sentences) description of the development, including its specific relevance to **`{output_country}`**.
                * Embed a relevant Markdown link *within* the description text: `[Descriptive Text](URL)`. Hyperlink 3-5 contextually relevant words. The URL should come from the OSINT report's `link` field.
                * If you reference a GTI perspective from a 'News Analysis' report, you may also include a link to it using its `report_id`.
        </OUTPUT_FORMAT>
        
        <CONSTRAINTS>
        * **Country Focus:** All selected stories MUST be relevant to `{output_country}`.
            * **Language:** The final output MUST be entirely in `{output_language}`.
            * **Item Count:** The newsletter should contain **8-10** story summaries.
            * **No CVE Table:** Do NOT generate a "Vulnerability Spotlight" table. This will be added later by the program. Focus only on writing the narrative summary.
            * **Recency:** Prioritize information from the last 24-48 hours for a daily brief, or the last week for a weekly brief.
            * **Linking:** Use *only* inline Markdown links. Every item must have at least one functional link to a source.
            * **Accuracy:** Report facts accurately based on the provided inputs. Do not hallucinate.
            * **No Sub-bullets:** Do not use nested bullet points within a summary item.
        </CONSTRAINTS>
    </PROMPT>
    """

def get_user_prompt(collections, output_country):
    """Creates the user-facing prompt for the Gemini model."""
    today_str = datetime.date.today().strftime("%A, %B %d, %Y")
    
    # Truncate the collections to avoid exceeding token limits
    collections_subset = collections[:450]
    
    return f"""
    Create a concise, engaging newsletter for cyber threat intelligence professionals protecting organizations and interests based in {output_country}.
    Use the following reports as source material.
    Begin each item in the newsletter summary (before the bold title) with a thematically appropriate emoji, following the bullet point. No duplicates; each item must have a unique emoji.
    Use Bold text for the section headers; do not use H2 headers.
    Select items with an eye to your {output_country} readership.
    Make sure you highlight concerns that would be relevant to {output_country} security professionals.

    Today's date is {today_str}

    REPORT_OBJECTS: {collections_subset}

    Output:
    """

async def generate_summary(session, api_key, model_name, system_instruction, user_prompt):
    """Calls the Gemini API to generate the summary."""
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "systemInstruction": {"parts": [{"text": system_instruction}]},
        "generationConfig": {
            "temperature": 0.6,
            "topP": 0.95,
            "topK": 64,
            "candidateCount": 1,
            "stopSequences": ["STOP!"],
        }
    }
    async with session.post(api_url, headers=headers, data=json.dumps(payload)) as response:
        response.raise_for_status()
        result = await response.json()
        return result['candidates'][0]['content']['parts'][0]['text']

def create_vulnerability_table(cve_details, output_language):
    """Creates a Markdown table from enriched CVE details."""
    title = "Vulnerability Spotlight"
    if output_language.lower() == 'german': title = "Schwachstellen-Spotlight"
    table_lines = [f"\n### {title}\n", "| CVE | Name | Vendor | CVSSv4 Score | Risk Rating | CWE Title | CISA KEV |", "|---|---|---|---|---|---|---|"]
    for cve in cve_details:
        row = (f"| {cve.get('cve_id', 'N/A')} | {cve.get('name', 'N/A')} | TBD | {cve.get('cvss_v4_score', 'N/A')} | {cve.get('risk_rating', 'N/A')} | {cve.get('cwe_title', 'N/A')} | {cve.get('cisa_kev', 'N/A')} |")
        table_lines.append(row)
    return "\n".join(table_lines)

# ==============================================================================
#  Main Callable Function
# ==============================================================================

async def generate_full_report(country, language, days, model, enrich_cve, source, gti_api_key=None, gemini_api_key=None):
    """
    Main logic to generate the full threat intelligence report.
    This function is called by the Streamlit front-end.
    """
    gti_api_key, gemini_api_key = load_env_vars(gti_api_key, gemini_api_key)
    start_date = f"{days}d"
    
    async with aiohttp.ClientSession() as session:
        collections = await fetch_reports(session, gti_api_key, country, source, start_date=start_date)
        if not collections:
            return "No reports found for the specified period."

        system_instruction = get_system_instruction(country, language)
        user_prompt = get_user_prompt(collections, country)
        
        summary_text = await generate_summary(session, gemini_api_key, model, system_instruction, user_prompt)
        final_report = summary_text

        if enrich_cve:
            cves_from_summary = extract_cves_from_text(summary_text)
            if cves_from_summary:
                print(f"✅ Extracted {len(cves_from_summary)} CVEs from summary.")
                cve_details = await fetch_vulnerability_details(session, gti_api_key, cves_from_summary)
                if cve_details:
                    vulnerability_table = create_vulnerability_table(cve_details, language)
                    final_report += "\n" + vulnerability_table
            else:
                print("ℹ️ No CVEs found in the generated summary to enrich.")
    
    return final_report

