# 🛠️ Implementation Plan: Contextual Underground Threat & Sentiment Intelligence System (CUTSIS)

**Repository Path:** `/Users/dominicchua/My_Drive/Github/VirusTotal/Python_Scripts/DTM/ddw_sentiment_analysis/standalone_code/`  
**Target Roadmap:** Phase 1 (Standalone Engine) $\to$ Phase 2 (Author Cross-Correlation) $\to$ Phase 3 (Actor Profiling & Python SDK) $\to$ Phase 4 (Analyst UX & Threat Actor API)

---

## Phase 1: Standalone Threat & Sentiment Engine (Current Focus)

### Objective
Deliver a streamlined, high-accuracy standalone CLI tool that gathers sliding context windows, extracts forum thread roots, and synthesizes intelligence into actionable threat severity, supply chain exposure, and community sentiment pulse without premature attribution.

### Milestone 1.1: GTI DDW Client Enhancements (`ddw_client.py`)
* [x] **Task 1.1.1: Implement Sliding Context Window**
  - Query `/previous_communications/{id}` and `/next_communications/{id}` for $\pm N$ chats.
  - Preserve all chats chronologically with original and translated text.
* [x] **Task 1.1.2: Implement Thread Root Post Retrieval**
  - Extract opening message (post #1) for forum threads (`conversation_thread`).
* [x] **Task 1.1.3: Container Profile & Metadata Caching**
  - Cache Telegram channel and dark web forum service metadata.

---

### Milestone 1.2: Streamlined CTI Prompt & Synthesis (`analyzer.py`)
* [x] **Task 1.2.1: Integrate Thread Root Grounding in Prompt**
  - Add Section `1b. FORUM THREAD ROOT CONTEXT` when post belongs to a `conversation_thread`.
* [x] **Task 1.2.2: Streamlined Output Schema**
  - Focus strictly on:
    - `threat_and_supply_chain`: `intent_category`, `threat_severity` (1–5), `is_actionable_threat`, `targeted_entities`, `targeted_sectors`, `targeted_technologies`, `explicitly_claimed_actor`.
    - `community_sentiment_and_reaction`: `reaction_status`, `buyer_interest_detected`, `vouches_detected`, `disputes_or_scam_warnings`, `supporting_evidence_quotes`, `reaction_narrative`.
    - `channel_intelligence`: theme, context takeaway, credibility.
    - `investigative_recommendation` and `executive_summary`.
* [x] **Task 1.2.3: Verify Prompt Delimiting & Injection Resistance**
  - Wrap all untrusted user content in `<<<UNTRUSTED_CONTENT>>>` with explicit security and attribution directives.

---

### Milestone 1.3: CLI Controls & JSON Export (`main.py`)
* [x] **Task 1.3.1: Command-Line Flags**
  - `--id <COMM_ID>`, `--window <N>`, `--output <PATH>`, `--dry-run`.
* [x] **Task 1.3.2: Terminal Output Cards**
  - Display container info, target previews, threat severity, targeted supply chain entities/sectors, and community reaction pulse.
* [x] **Task 1.3.3: Clean JSON Output Export**
  - Export full bundle + analysis matching future ingestion requirements.

---

## Phase 2: Cross-Platform Author Correlation & Reputation Augmentation

### Objective
Expand upon single-post evaluation by correlating the target author's handle or user ID across other underground forums and channels within a bounded temporal window, analyzing the sentiment and reputation of their posts in those environments, and feeding that historical context into the final post verdict.

### Milestone 2.1: Time-Framed Historical Retrieval
* [ ] **Task 2.1.1: Time-Framing Bounded Queries (`[T - 14d, T]`)**
  - Given target post timestamp $T$, calculate temporal boundaries (default: $T - 14$ days, configurable via CLI `--lookback-days`).
  - Restrict historical post retrieval and corroboration queries to this window to avoid conflating stale historical events.
* [ ] **Task 2.1.2: Multi-Platform Author Querying**
  - Search GTI DDW by `author.id` (Tier 1) and alias `author.name` (Tier 2) within the temporal window.
* [ ] **Task 2.1.3: Deterministic Behavioral Metrics**
  - Compute platform dispersion, copypasta broadcast rate, and active window span.

### Milestone 2.2: Cross-Channel Sentiment & Reputation Extraction
* [ ] **Task 2.2.1: Sentiment Extraction Across Platforms**
  - Analyze peer responses on other platforms within the time window (e.g. was this author vouched as a legitimate seller on BreachForums, or banned/disputed on XSS/Exploit?).
  - Classify historical reputation: `Established_Vouched`, `Mixed_Reputation`, `Known_Scammer_Ripper`, `Broadcast_Spammer`, `Unknown_New`.

### Milestone 2.3: Augmented Verdict Synthesis & Live GTI Corroboration
* [ ] **Task 2.3.1: Live GTI Intelligence Report Corroboration**
  - Query GTI reports or DDW search for extracted victim entities within the time frame to corroborate active breach disclosures.
* [ ] **Task 2.3.2: Augmented Synthesis Engine**
  - Combine local context + author reputation + GTI report matches to elevate or downgrade the final Estimative Probability.

---

## Phase 3: Forum & Threat Actor Profiling + Reusable Python Library / SDK

### Objective
Create persistent profiles for forums and threat actors, and package the evaluation capabilities into a clean, reusable Python library/SDK that other internal tools and projects can easily import and call.

### Milestone 3.1: Persistent Profiling
* [ ] **Task 3.1.1: Forum & Channel Profiling**
  - Track channel credibility baselines, spam ratios, and dominant attack themes.
* [ ] **Task 3.1.2: Threat Actor Dossier Models**
  - Aggregate actor aliases, historical targeted industries, and reputation trajectory into structured profiles.

### Milestone 3.2: Reusable Python Library / Entrypoint
* [ ] **Task 3.2.1: Package Engine as Reusable SDK**
  - Structure as an importable module (e.g. `from ddw_sentiment import evaluate_post, get_actor_profile`).
  - Provide simple programmatic APIs for other DTM / VirusTotal automation scripts to invoke.

---

## Phase 4: Analyst Web UX & Threat Actor API

### Objective
Provide a unified web-based command center for CTI analysts to visually inspect conversation windows and receive alerts, alongside an exposed REST API for threat actor intelligence.

### Milestone 4.1: Analyst Web Dashboard
* [ ] **Task 4.1.1: Visual Context Window & Threat Stream**
  - Real-time stream of incoming underground chatter with interactive $\pm N$ chat visualizer.
* [ ] **Task 4.1.2: Supply Chain Alerting Center**
  - Manage supply chain entity watchlists and dispatch webhooks (Slack, Teams, SIEM) on critical alerts.

### Milestone 4.2: Threat Actor REST API
* [ ] **Task 4.2.1: Expose REST/gRPC Endpoints**
  - Endpoints to query threat actor profiles, recent activity, sentiment trajectory, and associated supply chain incidents.
