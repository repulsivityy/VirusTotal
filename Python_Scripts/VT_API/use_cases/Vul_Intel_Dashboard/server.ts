import express from "express";
import path from "path";
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

function formatGtiTimestamp(ts: any): string | undefined {
  if (typeof ts === "number" && ts > 0) {
    const ms = ts < 10000000000 ? ts * 1000 : ts;
    return new Date(ms).toISOString().split("T")[0];
  }
  if (typeof ts === "string" && ts.trim()) {
    return ts.trim();
  }
  return undefined;
}

function stripHtmlTags(str: string): string {
  return str.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

function formatCpeLabel(str: string): string {
  return str.replace(/_/g, " ").replace(/\s+/g, " ").trim();
}

// Helper function to map direct VirusTotal / GTI API response to CveReport structure
function mapGtiResponse(cveId: string, data: any): any {
  const attrs = data.attributes || {};

  // 1. CVSS Details & Primary Score/Vector (strictly from GTI)
  const cvssDetails: any = {};
  if (attrs.cvss) {
    if (attrs.cvss.cvssv3_x) {
      cvssDetails.cvssv3 = {
        baseScore: attrs.cvss.cvssv3_x.base_score ?? null,
        temporalScore: attrs.cvss.cvssv3_x.temporal_score ?? null,
        vector: attrs.cvss.cvssv3_x.vector ?? null,
      };
    }
    if (attrs.cvss.cvssv3_x_translated) {
      cvssDetails.cvssv3Translated = {
        baseScore: attrs.cvss.cvssv3_x_translated.base_score ?? null,
        temporalScore: attrs.cvss.cvssv3_x_translated.temporal_score ?? null,
        vector: attrs.cvss.cvssv3_x_translated.vector ?? null,
      };
    }
    if (attrs.cvss.cvssv4_x) {
      cvssDetails.cvssv4 = {
        score: attrs.cvss.cvssv4_x.score ?? null,
        vector: attrs.cvss.cvssv4_x.vector ?? null,
        exploitMaturity: attrs.cvss.cvssv4_x.threat?.exploit_maturity ?? null,
      };
    }
  }

  let cvssScore: number | null =
    cvssDetails.cvssv4?.score ??
    cvssDetails.cvssv3Translated?.baseScore ??
    cvssDetails.cvssv3Translated?.temporalScore ??
    cvssDetails.cvssv3?.baseScore ??
    cvssDetails.cvssv3?.temporalScore ??
    null;

  let cvssVector: string =
    cvssDetails.cvssv4?.vector ||
    cvssDetails.cvssv3Translated?.vector ||
    cvssDetails.cvssv3?.vector ||
    "";

  // Fallback to GTI sources[].cvss if top-level attrs.cvss was not populated (prioritizing v4, then v3)
  if ((cvssScore === null || !cvssVector) && Array.isArray(attrs.sources)) {
    for (const src of attrs.sources) {
      const sCvss = src?.cvss;
      if (!sCvss) continue;
      const candidateScore =
        sCvss.cvssv4_x?.score ??
        sCvss.cvssv3_x_translated?.base_score ??
        sCvss.cvssv3_x?.base_score ??
        null;
      const candidateVec =
        sCvss.cvssv4_x?.vector ||
        sCvss.cvssv3_x_translated?.vector ||
        sCvss.cvssv3_x?.vector ||
        "";
      if (cvssScore === null && typeof candidateScore === "number") {
        cvssScore = candidateScore;
      }
      if (!cvssVector && candidateVec) {
        cvssVector = candidateVec;
      }
      if (cvssScore !== null && cvssVector) break;
    }
  }

  // 2. Risk Rating, Priority & Severity
  const riskRating = typeof attrs.risk_rating === "string" && attrs.risk_rating ? attrs.risk_rating : undefined;
  const predictedRiskRating =
    typeof attrs.predicted_risk_rating === "string" && attrs.predicted_risk_rating
      ? attrs.predicted_risk_rating
      : undefined;
  const priority = typeof attrs.priority === "string" && attrs.priority ? attrs.priority : undefined;

  let severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "MEDIUM";
  const ratingSource = (riskRating || predictedRiskRating || priority || "").toUpperCase();
  if (ratingSource.includes("CRITICAL") || ratingSource === "P0" || ratingSource === "P1") {
    severity = "CRITICAL";
  } else if (ratingSource.includes("HIGH") || ratingSource === "P2") {
    severity = "HIGH";
  } else if (ratingSource.includes("MEDIUM") || ratingSource === "P3") {
    severity = "MEDIUM";
  } else if (ratingSource.includes("LOW") || ratingSource === "P4") {
    severity = "LOW";
  } else if (cvssScore !== null) {
    severity = cvssScore >= 9.0 ? "CRITICAL" : cvssScore >= 7.0 ? "HIGH" : cvssScore >= 4.0 ? "MEDIUM" : "LOW";
  }

  // 3. EPSS Score & Percentile (strictly from GTI)
  let epssScore: number | undefined = undefined;
  let epssPercentile: number | undefined = undefined;
  if (attrs.epss && typeof attrs.epss === "object") {
    if (typeof attrs.epss.score === "number") {
      epssScore = attrs.epss.score;
    }
    if (typeof attrs.epss.percentile === "number") {
      epssPercentile = attrs.epss.percentile;
    }
  } else if (typeof attrs.epss === "number") {
    epssScore = attrs.epss;
  }

  // 4. Dates (strictly from GTI)
  const publishedDate = formatGtiTimestamp(attrs.date_of_disclosure) || formatGtiTimestamp(attrs.creation_date) || "";
  const creationDate = formatGtiTimestamp(attrs.creation_date);
  const lastModifiedDate = formatGtiTimestamp(attrs.last_modification_date);

  // 5. Exploitation State, Availability & Telemetry
  const exploitationState =
    typeof attrs.exploitation_state === "string" && attrs.exploitation_state ? attrs.exploitation_state : undefined;
  const exploitAvailability =
    typeof attrs.exploit_availability === "string" && attrs.exploit_availability ? attrs.exploit_availability : undefined;
  const exploitationConsequence =
    typeof attrs.exploitation_consequence === "string" && attrs.exploitation_consequence
      ? attrs.exploitation_consequence
      : undefined;
  const exploitationVectors = Array.isArray(attrs.exploitation_vectors)
    ? attrs.exploitation_vectors.filter((v: any) => typeof v === "string")
    : [];
  const riskFactors = Array.isArray(attrs.risk_factors)
    ? attrs.risk_factors.filter((r: any) => typeof r === "string")
    : [];
  const tags = Array.isArray(attrs.tags) ? attrs.tags.filter((t: any) => typeof t === "string") : [];

  const cisaKev =
    attrs.cisa_known_exploited &&
    (attrs.cisa_known_exploited.added_date ||
      attrs.cisa_known_exploited.due_date ||
      attrs.cisa_known_exploited.ransomware_use)
      ? {
          addedDate: formatGtiTimestamp(attrs.cisa_known_exploited.added_date),
          dueDate: formatGtiTimestamp(attrs.cisa_known_exploited.due_date),
          ransomwareUse: attrs.cisa_known_exploited.ransomware_use || undefined,
        }
      : undefined;

  const firstExploitationDate = formatGtiTimestamp(attrs.exploitation?.first_exploitation);
  const exploitReleaseDate = formatGtiTimestamp(attrs.exploitation?.exploit_release_date);
  const techDetailsReleaseDate = formatGtiTimestamp(attrs.exploitation?.tech_details_release_date);

  const expStateNorm = (exploitationState || "").trim().toLowerCase();
  const exploitedInTheWild =
    expStateNorm === "confirmed" ||
    expStateNorm === "wide" ||
    expStateNorm === "reported" ||
    tags.includes("observed_in_the_wild") ||
    tags.includes("was_zero_day") ||
    Boolean(cisaKev?.addedDate) ||
    cvssDetails.cvssv4?.exploitMaturity === "Attacked";

  const availNorm = (exploitAvailability || "").trim().toLowerCase();
  const pocAvailable =
    availNorm === "publicly available" ||
    availNorm === "trivial" ||
    availNorm === "privately held" ||
    tags.includes("has_exploits");

  const threatActors = Array.isArray(attrs.merged_actors)
    ? attrs.merged_actors.map((a: any) => (typeof a === "string" ? a : a?.name || "")).filter(Boolean)
    : Array.isArray(attrs.threat_actors)
    ? attrs.threat_actors.map((a: any) => (typeof a === "string" ? a : a?.name || "")).filter(Boolean)
    : [];

  // 6. Descriptions, Executive Summary, Analysis & Title
  const description = typeof attrs.description === "string" ? attrs.description : "";
  const executiveSummary = typeof attrs.executive_summary === "string" ? attrs.executive_summary : undefined;
  const analysis = typeof attrs.analysis === "string" ? attrs.analysis : undefined;
  const technicalDetails = analysis || description || "";
  const gtiInsights = executiveSummary || "";

  // Derive descriptive title from GTI fields if attrs.title is not present
  let title = "";
  if (typeof attrs.title === "string" && attrs.title.trim() && attrs.title.trim().toUpperCase() !== cveId) {
    title = attrs.title.trim();
  } else if (Array.isArray(attrs.vendor_fix_references)) {
    const vTitle = attrs.vendor_fix_references.find((r: any) => r && typeof r.title === "string" && r.title.trim())?.title;
    if (vTitle) title = vTitle.trim();
  }
  if (!title && Array.isArray(attrs.sources)) {
    const sTitle = attrs.sources.find((s: any) => s && typeof s.title === "string" && s.title.trim())?.title;
    if (sTitle) title = sTitle.trim();
  }
  if (!title && attrs.cwe?.title) {
    title = attrs.cwe.title;
  }
  if (!title) {
    title = attrs.name || cveId;
  }

  // 7. Remediation, Workarounds & References (strictly from GTI)
  const availableMitigation = Array.isArray(attrs.available_mitigation)
    ? attrs.available_mitigation.filter((m: any) => typeof m === "string")
    : [];
  const daysToPatch = typeof attrs.days_to_patch === "number" ? attrs.days_to_patch : null;

  const status =
    availableMitigation.length > 0
      ? availableMitigation.join(", ")
      : typeof attrs.remediation_status === "string" && attrs.remediation_status
      ? attrs.remediation_status
      : "No Known Mitigation";

  const fixedVersions = Array.isArray(attrs.fixed_versions) ? attrs.fixed_versions : [];

  let steps: string[] = [];
  if (Array.isArray(attrs.workarounds) && attrs.workarounds.length > 0) {
    steps = attrs.workarounds
      .filter((w: any) => typeof w === "string")
      .map((w: string) => stripHtmlTags(w))
      .filter((w: string) => w.length > 0);
  } else if (Array.isArray(attrs.remediation_steps)) {
    steps = attrs.remediation_steps
      .filter((s: any) => typeof s === "string")
      .map((s: string) => stripHtmlTags(s))
      .filter((s: string) => s.length > 0);
  }

  const vendorFixReferences: any[] = [];
  if (Array.isArray(attrs.vendor_fix_references)) {
    const seenVendorUrls = new Set<string>();
    for (const ref of attrs.vendor_fix_references) {
      if (!ref || !ref.url || seenVendorUrls.has(ref.url)) continue;
      seenVendorUrls.add(ref.url);
      vendorFixReferences.push({
        title: ref.title || ref.name || ref.unique_id || ref.url,
        url: ref.url,
        sourceName: ref.name || undefined,
        uniqueId: ref.unique_id || undefined,
        publishedDate: formatGtiTimestamp(ref.published_date),
      });
    }
  }

  const references: any[] = [];
  if (Array.isArray(attrs.sources)) {
    const seenUrls = new Set<string>();
    for (const s of attrs.sources) {
      if (!s || !s.url || seenUrls.has(s.url)) continue;
      seenUrls.add(s.url);
      references.push({
        title: s.title || s.source_description || s.name || s.unique_id || s.url,
        url: s.url,
        sourceName: s.name || undefined,
        uniqueId: s.unique_id || undefined,
        publishedDate: formatGtiTimestamp(s.published_date),
      });
    }
  }

  // 8. CWE & Affected Products (parsed from GTI attrs.cpes)
  const cwe =
    attrs.cwe && (attrs.cwe.id || attrs.cwe.title)
      ? {
          id: attrs.cwe.id || "",
          title: attrs.cwe.title || "",
        }
      : undefined;

  const affectedProducts: { vendor: string; product: string; versions: string }[] = [];
  if (Array.isArray(attrs.cpes) && attrs.cpes.length > 0) {
    const productMap = new Map<string, { vendor: string; product: string; versionSet: Set<string> }>();

    for (const cpeEntry of attrs.cpes) {
      const start = cpeEntry?.start_cpe;
      const end = cpeEntry?.end_cpe;
      if (!start && !end) continue;

      const rawVendor = start?.vendor || end?.vendor || "";
      const rawProduct = start?.product || end?.product || "";
      if (!rawVendor && !rawProduct) continue;

      const vendor = formatCpeLabel(rawVendor);
      const product = formatCpeLabel(rawProduct);
      const key = `${vendor.toLowerCase()}::${product.toLowerCase()}`;

      if (!productMap.has(key)) {
        productMap.set(key, { vendor, product, versionSet: new Set<string>() });
      }

      const startVer = start?.version ? String(start.version).trim() : "";
      const endVer = end?.version ? String(end.version).trim() : "";
      const startRel = cpeEntry.start_rel || "";
      const endRel = cpeEntry.end_rel || "";

      let versionLabel = "";
      if (startVer && endVer) {
        const sPrefix = startRel && startRel !== "=" ? `${startRel} ` : "";
        const ePrefix = endRel && endRel !== "=" ? `${endRel} ` : "";
        versionLabel = `${sPrefix}${startVer} to ${ePrefix}${endVer}`;
      } else if (startVer) {
        const sPrefix = startRel && startRel !== "=" ? `${startRel} ` : "";
        versionLabel = `${sPrefix}${startVer}`;
      } else if (endVer) {
        const ePrefix = endRel && endRel !== "=" ? `${endRel} ` : "";
        versionLabel = `${ePrefix}${endVer}`;
      }

      if (versionLabel && versionLabel !== "-" && versionLabel !== "*") {
        productMap.get(key)!.versionSet.add(versionLabel);
      }
    }

    for (const item of productMap.values()) {
      const versionsArr = Array.from(item.versionSet);
      affectedProducts.push({
        vendor: item.vendor,
        product: item.product,
        versions: versionsArr.length > 0 ? versionsArr.join(", ") : "All versions",
      });
    }
  }

  // 9. Counters & Targeting Metadata
  const rawCounters = attrs.counters || {};
  const counters = attrs.counters
    ? {
        files: rawCounters.files || 0,
        domains: rawCounters.domains || 0,
        ipAddresses: rawCounters.ip_addresses || 0,
        urls: rawCounters.urls || 0,
        iocs: rawCounters.iocs || 0,
        subscribers: rawCounters.subscribers || 0,
        attackTechniques: rawCounters.attack_techniques || 0,
      }
    : undefined;

  return {
    cveId: attrs.cve_id || cveId,
    mveId: attrs.mve_id || undefined,
    title,
    description,
    executiveSummary,
    analysis,
    severity,
    riskRating,
    predictedRiskRating,
    priority,
    cvssScore,
    cvssVector,
    cvssDetails: Object.keys(cvssDetails).length > 0 ? cvssDetails : undefined,
    epssScore,
    epssPercentile,
    cwe,
    publishedDate,
    creationDate,
    lastModifiedDate,
    exploitPatterns: {
      exploitedInTheWild,
      pocAvailable,
      exploitationState,
      exploitAvailability,
      exploitationConsequence,
      exploitationVectors,
      firstExploitationDate,
      exploitReleaseDate,
      techDetailsReleaseDate,
      cisaKev,
      riskFactors,
      tags,
      threatActors,
      technicalDetails,
    },
    remediation: {
      status,
      availableMitigation,
      daysToPatch,
      fixedVersions,
      steps,
      vendorFixReferences,
      references,
    },
    affectedProducts,
    counters,
    targetedIndustries: Array.isArray(attrs.targeted_industries) ? attrs.targeted_industries : [],
    targetedRegions: Array.isArray(attrs.targeted_regions) ? attrs.targeted_regions : [],
    operatingSystems: Array.isArray(attrs.operating_systems) ? attrs.operating_systems : [],
    gtiInsights,
    dataSource: "GTI_API" as const,
    groundingSources: references,
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
    const { createServer: createViteServer } = await import("vite");
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
