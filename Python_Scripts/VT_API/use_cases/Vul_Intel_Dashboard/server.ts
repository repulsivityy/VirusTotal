import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json());

// Initialize Gemini client lazily to avoid crashing on start if API key is not yet set
let aiClient: GoogleGenAI | null = null;

function cleanApiKey(key: any): string | null {
  if (typeof key !== "string") return null;
  const trimmed = key.trim();
  if (!trimmed || trimmed === "undefined" || trimmed === "null") return null;
  return trimmed;
}

function getAiClientWithKey(customKey?: string | null): GoogleGenAI | null {
  const apiKey = customKey || process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
}

function getAiClient(): GoogleGenAI | null {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return null;
    }
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return aiClient;
}

// Normalize CVE ID format (CVE-YYYY-NNNNN)
function normalizeCveId(cveId: string): string {
  return cveId.trim().toUpperCase().replace(/[^A-Z0-9-]/g, "");
}

// Validate CVE ID format
function isValidCveId(cveId: string): boolean {
  return /^CVE-\d{4}-\d{4,7}$/i.test(cveId);
}

// Helper function to map direct VirusTotal / GTI API response to CveReport structure
function mapGtiResponse(cveId: string, data: any): any {
  const attrs = data.attributes || {};

  // Compute severity and score based on cvssv3_x_translated, cvssv4_x, or legacy fields
  let cvssScore = 7.5;
  let cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

  if (attrs.cvss) {
    if (attrs.cvss.cvssv3_x_translated) {
      cvssScore = attrs.cvss.cvssv3_x_translated.base_score || attrs.cvss.cvssv3_x_translated.temporal_score || cvssScore;
      cvssVector = attrs.cvss.cvssv3_x_translated.vector || cvssVector;
    } else if (attrs.cvss.cvssv4_x) {
      cvssScore = attrs.cvss.cvssv4_x.score || cvssScore;
      cvssVector = attrs.cvss.cvssv4_x.vector || cvssVector;
    }
  } else {
    const legacyScore = attrs.cvss3_base_score || attrs.cvss3_score || attrs.cvss_score;
    if (legacyScore !== undefined) {
      cvssScore = typeof legacyScore === "number" ? legacyScore : parseFloat(legacyScore) || 7.5;
    }
    cvssVector = attrs.cvss3_vector || attrs.cvss3_vector_string || attrs.cvss_vector || cvssVector;
  }

  let severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "HIGH";
  const rating = (attrs.predicted_risk_rating || attrs.risk_rating || attrs.priority || attrs.severity || "").toUpperCase();
  if (rating.includes("CRITICAL") || rating === "P1") {
    severity = "CRITICAL";
  } else if (rating.includes("HIGH") || rating === "P2") {
    severity = "HIGH";
  } else if (rating.includes("MEDIUM") || rating === "P3") {
    severity = "MEDIUM";
  } else if (rating.includes("LOW") || rating === "P4") {
    severity = "LOW";
  } else {
    severity = cvssScore >= 9.0 ? "CRITICAL" : cvssScore >= 7.0 ? "HIGH" : cvssScore >= 4.0 ? "MEDIUM" : "LOW";
  }

  let epssScore = 0.10;
  if (attrs.epss) {
    if (typeof attrs.epss.score === "number") {
      epssScore = attrs.epss.score;
    } else if (typeof attrs.epss === "number") {
      epssScore = attrs.epss;
    } else if (typeof attrs.epss_score === "number") {
      epssScore = attrs.epss_score;
    }
  } else if (typeof attrs.epss_score === "number") {
    epssScore = attrs.epss_score;
  }

  let publishedDate = attrs.date_of_disclosure || attrs.creation_date || attrs.published_date || attrs.created_date || "";
  if (typeof publishedDate === "number") {
    const ms = publishedDate < 10000000000 ? publishedDate * 1000 : publishedDate;
    publishedDate = new Date(ms).toISOString().split("T")[0];
  } else if (!publishedDate) {
    publishedDate = new Date().toISOString().split("T")[0];
  }

  let lastModifiedDate = attrs.last_modification_date || attrs.last_modified_date || "";
  if (typeof lastModifiedDate === "number") {
    const ms = lastModifiedDate < 10000000000 ? lastModifiedDate * 1000 : lastModifiedDate;
    lastModifiedDate = new Date(ms).toISOString().split("T")[0];
  } else if (!lastModifiedDate) {
    lastModifiedDate = publishedDate;
  }

  const expState = (attrs.exploitation_state || "").toLowerCase();
  const exploitedInTheWild = attrs.exploited || attrs.active_exploitation || attrs.is_exploited || 
                             expState.includes("active") || expState.includes("known") || false;

  const avail = (attrs.exploit_availability || "").toLowerCase();
  const pocAvailable = attrs.poc_available || attrs.has_poc || 
                       avail.includes("public") || avail.includes("poc") || avail.includes("available") || false;

  const threatActors = Array.isArray(attrs.threat_actors) 
    ? attrs.threat_actors 
    : Array.isArray(attrs.merged_actors)
    ? attrs.merged_actors
    : [];

  const description = attrs.description || attrs.executive_summary || "No description provided in Google Threat Intelligence feed.";
  const technicalDetails = attrs.executive_summary || attrs.technical_details || attrs.description || "The exploit mechanisms, attack vectors, and runtime payloads are currently documented in official vendor catalogs.";

  const status = attrs.remediation_status || attrs.status || "Mitigation Available";
  const fixedVersions = Array.isArray(attrs.fixed_versions) ? attrs.fixed_versions : [];
  
  let steps: string[] = [];
  if (Array.isArray(attrs.remediation_steps)) {
    steps = attrs.remediation_steps;
  } else if (attrs.mitigation || attrs.remediation) {
    const rawRem = attrs.mitigation || attrs.remediation;
    if (typeof rawRem === "string") {
      steps = rawRem.split("\n").map(s => s.trim()).filter(s => s.length > 0);
    }
  }
  if (steps.length === 0) {
    if (attrs.workarounds && Array.isArray(attrs.workarounds) && attrs.workarounds.length > 0) {
      steps = attrs.workarounds;
    } else {
      steps = [
        "Consult the official vendor product security advisory to fetch and deploy the designated software update.",
        "Isolate external-facing network ingress paths to affected servers where feasible.",
        "Deploy custom intrusion prevention signatures (IPS/IDS) targeting common serialized patterns of this CVE."
      ];
    }
  }

  let references: { title: string; url: string }[] = [];
  if (Array.isArray(attrs.sources)) {
    references = attrs.sources
      .filter((s: any) => s && s.url)
      .map((s: any) => ({
        title: s.name || "Threat Intel Source",
        url: s.url
      }));
  }
  
  if (references.length === 0 && Array.isArray(attrs.references)) {
    references = attrs.references.map((ref: any) => {
      if (typeof ref === "string") {
        return { title: "Vendor Advisory Link", url: ref };
      }
      return { title: ref.title || "Official Resource", url: ref.url || ref.uri || "" };
    });
  } else if (references.length === 0 && Array.isArray(attrs.urls)) {
    references = attrs.urls.map((url: any) => ({ title: "Security Bulletin", url }));
  }

  if (references.length === 0) {
    references = [
      { title: "NVD Portal Entry", url: `https://nvd.nist.gov/vuln/detail/${cveId}` },
      { title: "MITRE CVE Database", url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}` }
    ];
  }

  let affectedProducts: { vendor: string; product: string; versions: string }[] = [];
  if (attrs.cwe) {
    affectedProducts.push({
      vendor: "CWE-aligned Software",
      product: attrs.cwe.title || "Vulnerable System Component",
      versions: attrs.cwe.id || "All unmitigated releases"
    });
  }
  if (Array.isArray(attrs.products)) {
    const productsMapped = attrs.products.map((p: any) => {
      if (typeof p === "string") {
        return { vendor: "Vendor", product: p, versions: "Vulnerable Versions" };
      }
      return {
        vendor: p.vendor || "Affected Vendor",
        product: p.product || p.name || "Software Package",
        versions: p.versions || p.version || "Vulnerable versions range"
      };
    });
    affectedProducts.push(...productsMapped);
  } else if (Array.isArray(attrs.affected_products)) {
    const productsMapped = attrs.affected_products.map((p: any) => ({
      vendor: p.vendor || "Vendor",
      product: p.product || "Product",
      versions: p.versions || "Vulnerable"
    }));
    affectedProducts.push(...productsMapped);
  }
  if (affectedProducts.length === 0) {
    affectedProducts = [
      { vendor: "Enterprise Vendor", product: "Affected Module Package", versions: "Vulnerable active builds" }
    ];
  }

  let gtiInsights = attrs.gti_insights || "";
  if (!gtiInsights) {
    const tagsStr = Array.isArray(attrs.exploitation_vectors) && attrs.exploitation_vectors.length > 0
      ? ` Exploitation Vectors identified: ${attrs.exploitation_vectors.join(", ")}.`
      : "";
    const pRisk = attrs.predicted_risk_rating ? ` Predicted Risk Rating is compiled as ${attrs.predicted_risk_rating}.` : "";
    gtiInsights = `Successfully compiled threat report from direct Google Threat Intelligence feed.${tagsStr}${pRisk}`;
  }

  return {
    cveId,
    title: attrs.title || `${cveId} Vulnerability Report`,
    description,
    severity,
    cvssScore,
    cvssVector,
    epssScore,
    publishedDate,
    lastModifiedDate: lastModifiedDate || undefined,
    exploitPatterns: {
      exploitedInTheWild,
      pocAvailable,
      threatActors,
      technicalDetails
    },
    remediation: {
      status,
      fixedVersions,
      steps,
      references
    },
    affectedProducts,
    gtiInsights,
    dataSource: "GTI_API" as const,
    groundingSources: references
  };
}

// Helper to map direct GTI associations responses to CveAssociation schema
function mapGtiAssociationsResponse(dataArray: any[]): any[] {
  if (!Array.isArray(dataArray)) return [];
  
  return dataArray.map((item: any) => {
    const attrs = item.attributes || {};
    
    // Parse creation and modification dates
    let creationDate = "";
    if (typeof attrs.creation_date === "number") {
      creationDate = new Date(attrs.creation_date * 1000).toISOString().split("T")[0];
    }
    
    let lastModificationDate = "";
    if (typeof attrs.last_modification_date === "number") {
      lastModificationDate = new Date(attrs.last_modification_date * 1000).toISOString().split("T")[0];
    }

    // Parse motivations
    let motivations: string[] = [];
    if (Array.isArray(attrs.motivations)) {
      motivations = attrs.motivations.map((m: any) => {
        if (typeof m === "string") return m;
        return m.value || m.name || "";
      }).filter((m: string) => m.length > 0);
    }

    // Parse counters
    const rawCounters = attrs.counters || {};
    const counters = {
      files: rawCounters.files || 0,
      domains: rawCounters.domains || 0,
      ipAddresses: rawCounters.ip_addresses || rawCounters.ipAddresses || 0,
      urls: rawCounters.urls || 0,
      iocs: rawCounters.iocs || 0,
      subscribers: rawCounters.subscribers || 0,
      attackTechniques: rawCounters.attack_techniques || rawCounters.attackTechniques || 0,
    };

    return {
      id: item.id || `collection--${Math.random().toString(36).substr(2, 9)}`,
      type: item.type || "collection",
      collectionType: attrs.collection_type || attrs.collectionType || "campaign",
      name: attrs.name || "Associated Campaign Report",
      description: attrs.description || "Associated threat campaign detected by Google Threat Intelligence feeds.",
      origin: attrs.origin || "Google Threat Intelligence",
      creationDate: creationDate || undefined,
      lastModificationDate: lastModificationDate || undefined,
      counters,
      targetedRegions: Array.isArray(attrs.targeted_regions) ? attrs.targeted_regions : [],
      sourceRegion: attrs.source_region || undefined,
      altNames: Array.isArray(attrs.alt_names) ? attrs.alt_names : [],
      motivations
    };
  });
}

// Config check endpoint
app.get("/api/config", (req, res) => {
  res.json({
    hasServerGtiKey: !!(process.env.GTI_API_KEY || process.env.VIRUSTOTAL_API_KEY),
    hasServerGeminiKey: !!process.env.GEMINI_API_KEY,
  });
});

// Core CVE Threat intelligence endpoint
app.get("/api/cve/:id", async (req, res) => {
  const rawId = req.params.id;
  const cveId = normalizeCveId(rawId);

  if (!isValidCveId(cveId)) {
    return res.status(400).json({
      error: "Invalid CVE ID format. Correct format is CVE-YYYY-NNNN or CVE-YYYY-NNNNN (e.g., CVE-2023-38831).",
    });
  }

  const clientGtiKey = cleanApiKey(req.headers["x-gti-key"]);
  const gtiKey = clientGtiKey || process.env.GTI_API_KEY || process.env.VIRUSTOTAL_API_KEY;

  // GTI Key is critical. If not configured, ask user to enter a valid GTI key
  if (!gtiKey) {
    return res.status(400).json({
      error: "Google Threat Intelligence API key is not configured. Please enter a valid GTI API Key in the settings panel to fetch intelligence data.",
    });
  }

  try {
    const objectId = `vulnerability--${cveId.toLowerCase()}`;
    console.log(`Querying VirusTotal / GTI API collections for ${objectId}...`);
    const vtUrl = `https://www.virustotal.com/api/v3/collections/${objectId}`;
    const response = await fetch(vtUrl, {
      headers: {
        "x-apikey": gtiKey,
      },
    });

    if (response.ok) {
      const json = await response.json();
      if (json && json.data) {
        const directReport = mapGtiResponse(cveId, json.data);
        return res.json(directReport);
      } else {
        return res.status(500).json({
          error: `Failed to compile threat report for ${cveId}. Invalid response format from GTI.`,
        });
      }
    } else {
      console.warn(`GTI/VirusTotal API query failed with status: ${response.status}.`);
      if (response.status === 404) {
        return res.status(404).json({
          error: `Vulnerability ${cveId} was not found in the Google Threat Intelligence database.`,
        });
      } else {
        return res.status(response.status).json({
          error: `Failed to query Google Threat Intelligence API (Status: ${response.status}).`,
        });
      }
    }
  } catch (err: any) {
    console.error("Error during direct API query:", err);
    return res.status(500).json({
      error: `Failed to query Google Threat Intelligence API: ${err.message || err}`,
    });
  }
});

// Associations lookup route
app.get("/api/cve/:id/associations", async (req, res) => {
  const rawId = req.params.id;
  const cveId = normalizeCveId(rawId);

  if (!isValidCveId(cveId)) {
    return res.status(400).json({
      error: "Invalid CVE ID format. Correct format is CVE-YYYY-NNNN or CVE-YYYY-NNNNN (e.g., CVE-2023-38831).",
    });
  }

  const clientGtiKey = cleanApiKey(req.headers["x-gti-key"]);
  const gtiKey = clientGtiKey || process.env.GTI_API_KEY || process.env.VIRUSTOTAL_API_KEY;

  if (!gtiKey) {
    return res.status(400).json({
      error: "Google Threat Intelligence API key is not configured. Please enter a valid GTI API Key in the settings panel to fetch intelligence data.",
    });
  }

  try {
    const objectId = `vulnerability--${cveId.toLowerCase()}`;
    console.log(`Querying VirusTotal / GTI API associations for ${objectId}...`);
    const vtUrl = `https://www.virustotal.com/api/v3/collections/${objectId}/associations?limit=10`;
    const response = await fetch(vtUrl, {
      headers: {
        "x-apikey": gtiKey,
      },
    });

    if (response.ok) {
      const json = await response.json();
      if (json && Array.isArray(json.data)) {
        const parsed = mapGtiAssociationsResponse(json.data);
        return res.json(parsed);
      } else {
        return res.json([]);
      }
    } else {
      console.warn(`GTI/VirusTotal associations query failed with status: ${response.status}.`);
      return res.json([]);
    }
  } catch (err: any) {
    console.error("Error during direct associations API query:", err);
    return res.json([]);
  }
});

// Latest News summaries endpoint
app.get("/api/cve/:id/news", async (req, res) => {
  const rawId = req.params.id;
  const cveId = normalizeCveId(rawId);

  if (!isValidCveId(cveId)) {
    return res.status(400).json({
      error: "Invalid CVE ID format.",
    });
  }

  const clientGeminiKey = cleanApiKey(req.headers["x-gemini-key"]);
  const geminiKey = clientGeminiKey || process.env.GEMINI_API_KEY;

  const ai = getAiClientWithKey(geminiKey);
  if (!ai) {
    return res.status(400).json({
      error: "Gemini API key is required to fetch and summarize latest news.",
    });
  }

  try {
    console.log(`Running web-grounded search for latest news on ${cveId}...`);
    const prompt = `Search for the latest news, blogs, and security advisories from the last 12-24 months regarding ${cveId}.
Provide a high-quality, professional summary of the latest news in exactly 5 to 8 sentences.
Focus on current exploitation reports, newly released exploit tools, patch advisories, vendor updates, or notable security incidents involving ${cveId}.
Do not include metadata, preambles, or greetings. Just return the 5-8 sentence summary.`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        tools: [{ googleSearch: {} }],
      },
    });

    const summary = response.text || "";

    // Extract grounding URLs
    const sources: { title: string; url: string }[] = [];
    const chunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks;
    if (chunks && Array.isArray(chunks)) {
      for (const chunk of chunks) {
        if (chunk.web && chunk.web.uri) {
          sources.push({
            title: chunk.web.title || "News Source",
            url: chunk.web.uri,
          });
        }
      }
    }

    return res.json({
      summary,
      sources,
    });
  } catch (err: any) {
    console.error("Failed to generate news summary:", err);
    return res.status(502).json({
      error: `Failed to compile news summary: ${err.message || err}`,
    });
  }
});

// Configure Vite and Asset Serving
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
    console.log("Vite dev middleware mounted.");
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
    console.log("Production static files server mounted.");
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is booted and listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
