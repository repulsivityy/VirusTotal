# app.py

import streamlit as st
import asyncio
from report_generator import generate_full_report

# --- Streamlit Page Configuration ---
st.set_page_config(
    page_title="GTI OSINT Country-Specific Threat Briefing",
    page_icon="🤖",
    layout="wide"
)

# --- UI Rendering ---
st.title("GTI Country-Specific Threat Briefing Generator")

# --- Sidebar for User Inputs ---
with st.sidebar:
    st.header("⚙️ Report Configuration")
    
    country = st.text_input("Country", "Singapore", help="The country to focus the report on.")
    language = st.selectbox("Language", ["English", "Chinese", "Traditional Chinese", "French", "German", "Japanese", "Korean", "Malay", "Portugese", "Spanish", "Thai", "Vietnamese"])
    days = st.slider("Days of History", min_value=1, max_value=30, value=7, help="How many days back to fetch reports from.")
    
    source_option = st.selectbox(
        "Report Source", 
        ["Crowdsourced", "GTI", "Both"],
        help="Filter reports by their origin. 'Crowdsourced' excludes GTI, 'GTI' is only Google Threat Intelligence, 'Both' includes all sources."
    )

    model = st.selectbox("Gemini Model", ["gemini-2.5-flash", "gemini-2.5-pro"])
    enrich_cve = st.toggle("Enrich CVEs?", value=True, help="If enabled, extracts CVEs from the summary and adds a details table.")

    st.header("🔑 API Keys")
    gti_api_key_input = st.text_input("GTI API Key", type="password", help="Enter your GTI API Key")
    gemini_api_key_input = st.text_input("Gemini API Key", type="password", help="Enter your Gemini API Key.")


# --- Main Application Logic ---
if st.button("Generate Report", type="primary", use_container_width=True):
    with st.spinner(f"🔍 Fetching reports and generating summary for **{country}**... This may take a moment."):
        try:
            source_for_api = source_option.lower()

            final_report = asyncio.run(
                generate_full_report(
                    country=country,
                    language=language,
                    days=days,
                    model=model,
                    enrich_cve=enrich_cve,
                    source=source_for_api,
                    gti_api_key=gti_api_key_input,
                    gemini_api_key=gemini_api_key_input
                )
            )
            st.success("Report generated successfully!")
            st.markdown("---")
            st.markdown(final_report)
        except Exception as e:
            st.error(f"An error occurred: {e}")
            st.error("Please check your API keys and ensure the services are reachable.")
else:
    st.info("Configure the report parameters and provide API keys in the sidebar, then click 'Generate Report'.")

