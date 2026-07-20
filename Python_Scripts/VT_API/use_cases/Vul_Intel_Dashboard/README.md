# Vulnerability Threat Intelligence Dashboard

A modern, high-precision threat intelligence dashboard powered by the **Google Threat Intelligence (GTI) API** and **Gemini 3.5 Flash** with Google Search Grounding. 

This dashboard provides security teams, developers, and analysts with instant, deep insights into CVE entries, active exploit patterns, affected products, threat campaigns, and live news summaries.

---

## 🚀 Key Features

* **CVE Analyzer**: Queries the direct Google Threat Intelligence API to retrieve vulnerability details, CVSS scores, and EPSS metrics.
* **Exploit Telemetry**: Identifies whether a CVE is actively exploited in-the-wild, checks public PoC availability, and links associated Advanced Persistent Threat (APT) groups.
* **Threat Campaign Mapping**: Indexes adversary campaigns, malware families, and malicious files associated with the vulnerability.
* **Grounded News Summary**: Utilizes Gemini with Google Search Grounding to fetch, cross-reference, and summarize live news and security bulletins from the last 12–24 months in exactly 5 to 8 sentences.
* **Modern Dark-Mode UI**: Features clean layouts, responsive tabs, dynamic radial progress indicators, and easy JSON export utilities.

---

## 🔑 API Key Configuration

The application operates in two distinct modes for credential safety:

### 1. Client-Side (UX Configuration)
If no server-side keys are configured, the web interface will display a credential warning. End users can open the settings drawer in the UX and configure:
* **Google Threat Intelligence API Key** (your Google Threat Intelligence API Key)
* **Gemini API Key** (optional, for web-grounded news summary)

These keys are saved locally in the browser's `localStorage` and sent safely via request headers.

### 2. Server-Side (Environment Configuration)
You can configure global API keys on the server using environment variables or a `.env` file at the root:
```env
# Your Google Threat Intelligence API Key (Critical)
GTI_API_KEY="your_gti_api_key"

# Your Gemini API Key (Optional, for news summary)
GEMINI_API_KEY="your_gemini_api_key"
```

---

## 🛠️ Run Locally

### Prerequisites
* [Node.js](https://nodejs.org/) (v18 or higher)

### Steps
1. **Install Dependencies**:
   ```bash
   npm install
   ```
2. **Setup Environment**:
   Create a `.env` file at the root using the template above or configure keys directly in the UI settings drawer once the app is running.
3. **Start the Development Server**:
   ```bash
   npm run dev
   ```
   Open your browser and navigate to `http://localhost:3000`.

---

## ☁️ Deploy to Google Cloud Run

We provide a deployment script to easily package and run the dashboard in containerized production environments.

### 1. Make the script executable
```bash
chmod +x deploy.sh
```

### 2. Run the deployment script
```bash
./deploy.sh
```
* The script automatically builds your container image using **Google Cloud Build** and deploys it to **Google Cloud Run**.
* If you have credentials in your local `.env`, the script will automatically sync them securely to **Google Secret Manager** and mount them to the container instance. If not, it will deploy a clean instance that defaults to client-side UX key configuration.