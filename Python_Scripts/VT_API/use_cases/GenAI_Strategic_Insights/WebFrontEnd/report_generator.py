# report_generator.py

import os
import re
import asyncio
import datetime
from tqdm import tqdm
import aiohttp
import json

# ==============================================================================
#  Configuration and Initialization (Moved from main script)
# ==============================================================================

def load_env_vars():
    gti_api_key = os.getenv("GTI_APIKEY")
    gemini_api_key = os.getenv("GEMINI_APIKEY")
    if not all([gti_api_key, gemini_api_key]):
        raise ValueError("Missing API keys. Please set GTI_APIKEY and GEMINI_APIKEY in your .env file.")
    return gti_api_key, gemini_api_key

# ==============================================================================
#  All your existing helper functions (unchanged)
# ==============================================================================

def parse_report_from_api(report_data):
    attrs = report_data.get('attributes', {})
    creation_timestamp = attrs.get('creation_date')
    creation_date_str = datetime.datetime.fromtimestamp(creation_timestamp).isoformat() if creation_timestamp else ''
    return {
        'report_id': report_data.get('id', ''),
        'name': attrs.get('name', ''),
        'link': report_data.get('links', {}).get('self', '').replace('/api/v3/', '/'),
        'content': attrs.get('content', '')
    }

def extract_cves_from_text(text):
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    return set(cve_pattern.findall(text))

def parse_vulnerability_from_api(cve_id, vuln_data):
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
    headers = {'x-apikey': gti_api_key, 'x-tool': 'AI Content Generation'}
    async def fetch_single_cve(cve_id):
        url = f"https://www.virustotal.com/api/v3/collections/vulnerability--{cve_id.lower()}"
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return parse_vulnerability_from_api(cve_id, await response.json())
                return None
        except Exception:
            return None

    tasks = [fetch_single_cve(cve) for cve in cves]
    results = [result for result in await asyncio.gather(*tasks) if result]
    return results

async def fetch_reports(session, gti_api_key, start_date='5d', limit=400):
    base_url = 'https://www.virustotal.com/api/v3/collections'
    headers = {'x-apikey': gti_api_key, 'x-tool': 'AI Content Generation'}
    params = {
        "filter": f"collection_type:report creation_date:{start_date}+",
        "order": "creation_date-", "limit": 40
    }
    collections, next_url = [], base_url
    with tqdm(total=limit, desc="Fetching GTI Reports") as pbar:
        while next_url and len(collections) < limit:
            async with session.get(next_url, headers=headers, params=params) as response:
                if params: params = None
                response.raise_for_status()
                data = await response.json()
                fetched_data = data.get('data', [])
                parsed = [parse_report_from_api(item) for item in fetched_data]
                collections.extend(parsed[:min(len(parsed), limit - len(collections))])
                pbar.update(len(parsed[:min(len(parsed), limit - len(collections))]))
                next_url = data.get('links', {}).get('next') if len(collections) < limit else None
    return collections

def get_system_instruction(output_country, output_language):
    # Same system prompt from your original script
    return f"""
    <PROMPT>
        <ROLE>You are a highly sophisticated AI simulating a skilled writer with the combined expertise of a **seasoned Threat Intelligence Analyst** and a **meticulous News Editor**...</ROLE>
        <TASK>Generate a **compelling, concise, and engaging weekly threat intelligence newsletter** focused on the most important landscape developments relevant to the specified {output_country}...</TASK>
        <CONSTRAINTS>**No CVE Table:** Do NOT generate a "Vulnerability Spotlight" table. This will be added later by the program. Focus only on writing the narrative summary...</CONSTRAINTS>
    </PROMPT>
    """

def get_user_prompt(collections, output_country):
    today_str = datetime.date.today().strftime("%A, %B %d, %Y")
    return f"Create a concise, engaging newsletter for cyber threat intelligence professionals in {output_country}. Today's date is {today_str}. REPORT_OBJECTS: {collections[:400]}"

async def generate_summary(session, api_key, model_name, system_instruction, user_prompt):
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "systemInstruction": {"parts": [{"text": system_instruction}]},
        "generationConfig": {"temperature": 0.6, "topP": 0.95, "topK": 64, "candidateCount": 1}
    }
    async with session.post(api_url, headers=headers, data=json.dumps(payload)) as response:
        response.raise_for_status()
        result = await response.json()
        return result['candidates'][0]['content']['parts'][0]['text']

def create_vulnerability_table(cve_details, output_language):
    title = "Vulnerability Spotlight"
    if output_language.lower() == 'german': title = "Schwachstellen-Spotlight"
    table_lines = [f"**{title}**", "| CVE | Name | Vendor | CVSSv4 Score | Risk Rating | CWE Title | CISA KEV |", "|---|---|---|---|---|---|---|"]
    for cve in cve_details:
        row = (f"| {cve.get('cve_id', 'N/A')} | {cve.get('name', 'N/A')} | TBD | {cve.get('cvss_v4_score', 'N/A')} | {cve.get('risk_rating', 'N/A')} | {cve.get('cwe_title', 'N/A')} | {cve.get('cisa_kev', 'N/A')} |")
        table_lines.append(row)
    return "\n".join(table_lines)

# ==============================================================================
#  Main Callable Function
# ==============================================================================

async def generate_full_report(country, language, days, model, enrich_cve):
    """
    This function contains the entire logic to generate the report.
    It's called by the Streamlit front-end.
    """
    gti_api_key, gemini_api_key = load_env_vars()
    start_date = f"{days}d"
    
    async with aiohttp.ClientSession() as session:
        collections = await fetch_reports(session, gti_api_key, start_date=start_date)
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
                    final_report += "\n\n" + vulnerability_table
            else:
                print("ℹ️ No CVEs found in the generated summary to enrich.")
    
    return final_report