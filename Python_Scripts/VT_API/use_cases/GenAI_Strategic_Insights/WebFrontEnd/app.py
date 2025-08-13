# app.py

import streamlit as st
import asyncio
import datetime
from report_generator import generate_full_report

# --- Streamlit Page Configuration ---
st.set_page_config(
    page_title="GTI Threat Briefing",
    page_icon="🤖",
    layout="wide"
)

# --- UI Rendering ---
st.title("GTI Country-Specific Threat Briefing Generator")

# --- Sidebar for User Inputs ---
with st.sidebar:
    st.header("Report Configuration")
    
    country = st.text_input("Country", "Singapore")
    language = st.selectbox("Language", ["English", "German", "Japanese", "Spanish"])
    days = st.slider("Days of History", min_value=1, max_value=30, value=7)
    model = st.selectbox("Gemini Model", ["gemini-1.5-flash", "gemini-1.5-pro"])
    enrich_cve = st.toggle("Enrich CVEs?", value=True, help="If enabled, extracts CVEs from the summary and adds a details table.")

# --- Main Application Logic ---
if st.button("Generate Report", type="primary"):
    with st.spinner(f"🔍 Fetching reports and generating summary for {country}..."):
        try:
            # Use asyncio.run() to execute our async function from the sync Streamlit environment
            final_report = asyncio.run(
                generate_full_report(
                    country=country,
                    language=language,
                    days=days,
                    model=model,
                    enrich_cve=enrich_cve
                )
            )
            st.success("Report generated successfully!")
            st.markdown("---")
            st.markdown(final_report)
        except Exception as e:
            st.error(f"An error occurred: {e}")
            st.error("Please check your API keys in the .env file and ensure the services are reachable.")

else:
    st.info("Configure the report parameters in the sidebar and click 'Generate Report'.")