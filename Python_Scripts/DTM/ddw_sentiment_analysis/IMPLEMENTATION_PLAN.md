# 🛠️ Implementation Plan: Contextual Underground Threat & Sentiment Intelligence System (CUTSIS)

**Repository Path:** `ddw_sentiment_analysis/standalone_code/`  
**Target Roadmap:** Phase 1 (Standalone Engine) $\to$ Phase 2 (Author Cross-Correlation) $\to$ Phase 3 (Actor Profiling & Python SDK) $\to$ Phase 4 (Analyst UX & Threat Actor API)

---

## Phase 1: Standalone Threat & Sentiment Engine (Current Focus)

### Objective
Deliver a streamlined, high-accuracy standalone CLI tool that gathers sliding context windows, extracts forum thread roots, and synthesizes intelligence into actionable Words of Estimative Probability (WEP), supply chain exposure, and community sentiment pulse without premature attribution.

### Milestone 1.1: GTI DDW Client Enhancements (`ddw_client.py`)
* [x] **Task 1.1.1: Implement Sliding Context Window**
  - Query `/previous_communications/{id}` and `/next_communications/{id}` for $\pm N$ chats.
  - Preserve all chats chronologically with original and translated text.
* [x] **Task 1.1.2: Implement Thread Root (`Post #1`) Retrieval**
  - Walk backward via public `/ddw_conversation_threads/{id}/previous_communications/{comm_id}?limit=40` (up to 15 hops / 600 replies) to extract `Post #1` (`thread_root`), author handle, and bilingual text.
* [x] **Task 1.1.3: Container Profile & Metadata Caching**
  - Resolve and cache both dark web forum/platform (`service` via `/ddw_services/{id}`) and channel/sub-board (`communication_channel` via `/ddw_communication_channels/{id}`) metadata.
* [x] **Task 1.1.4: Attach Deterministic Signals to the Context Bundle**
  - `get_context_window()` calls `context_signals.analyze_context_signals(...)` once per bundle and exposes `context_insights` (commentary strings) and `handle_mentions` (per-handle records). `compute_context_insights()` remains as a thin commentary-only wrapper for callers of the previous API.

---

### Milestone 1.2: Streamlined CTI Prompt & Synthesis (`analyzer.py`)
* [x] **Task 1.2.1: Integrate Thread Root Grounding in Prompt**
  - Add Section `1b. FORUM THREAD ROOT CONTEXT` when post belongs to a `conversation_thread`.
* [x] **Task 1.2.2: Streamlined WEP Output Schema**
  - Focus strictly on:
    - `threat_and_supply_chain`: `intent_category`, `estimative_probability` (`level`, `probability_range`, `criteria_matched`, `rationale`), `is_actionable_threat`, `explicitly_claimed_actor`, `targeted_entities`, `targeted_sectors`, `targeted_technologies`.
    - `community_sentiment_and_reaction`: `reaction_status`, `buyer_interest_detected`, `vouches_detected`, `disputes_or_scam_warnings`, `supporting_evidence_quotes`, `reaction_narrative`.
    - `channel_intelligence`: `primary_theme`, `channel_context_takeaway`, `channel_credibility`.
    - `behavioral_commentary`, `investigative_recommendation`, `analytic_scope_disclaimer`, and `executive_summary`.
* [x] **Task 1.2.3: Verify Prompt Delimiting & Injection Resistance**
  - Wrap all untrusted user content in `<<<UNTRUSTED_CONTENT>>>` with explicit security and attribution directives.
* [x] **Task 1.2.4: Section `1d` — Observable Context Signals with Reading Rules**
  - Inject the deterministic commentary lines (sanitized, inside `<<<UNTRUSTED_CONTENT>>>`) preceded by rules: call-out ≠ promotion; relayed/parroted ≠ endorsement; bot handle may be benign; do not assert same-operator links beyond the signal. `behavioral_commentary` schema text mirrors the same vocabulary and the fixed "Standard organic post…" fallback.

---

### Milestone 1.3: CLI Controls & JSON Export (`main.py`)
* [x] **Task 1.3.1: Command-Line Flags**
  - `--id <COMM_ID>`, `--window <N>`, `--output <PATH>`, `--dry-run`, `--profile-author`, `--author-history-limit <N>`, `--lookback-days <N>`, `--author <NAME>`, `--channel <NAME>`.
* [x] **Task 1.3.2: Terminal Output Cards**
  - Display container info, target previews, WEP probability level/range and rationale, targeted supply chain entities/sectors/tech, and community reaction pulse.
* [x] **Task 1.3.3: Clean JSON Output Export**
  - Export full bundle + analysis matching future ingestion requirements.
* [x] **Task 1.3.4: Window Floor Enforcement**
  - `--window` is clamped to 1–40, then raised to `MIN_CONTEXT_WINDOW` (7) with an ℹ️ console note; both `window_size_requested` and `window_size_configured` are exported.
* [x] **Task 1.3.5: Commentary & Handle Table Rendering**
  - Print `💡 Observable Context Commentary` bullets and a `🔗 @Handle Classification` table (verdict, bot role, promoter / relayed / call-out / neutral counts; up to 8 rows, `mention_only` rows hidden unless the handle is in the target post). `behavioral_commentary` is shown in the CTI highlights after an LLM run.
* [x] **Task 1.3.6: Dry-Run Export & `.env` Autoload**
  - `--dry-run --output` writes the record with `"analysis": null`; API keys are also read from `./.env`, `standalone_code/.env`, its parent `.env`, or `~/.env` without overriding exported variables.

---

### Milestone 1.4: Deterministic Behavioral Signals (`context_signals.py`, no network)
* [x] **Task 1.4.1: Threshold Constants & Window Floor**
  - `MIN_CONTEXT_WINDOW = 7`, `BROADCAST_MIN_HISTORY = 3`, `BROADCAST_MIN_RATE = 0.5`, `PAIRED_MEDIA_MAX_GAP_SEC = 5`, `VELOCITY_RADIUS_SEC = 90`, `VELOCITY_MIN_MESSAGES = 4`, `VELOCITY_MIN_SENDERS = 4`, `UNLOCK_REPLY_MAX_CHARS = 20`, `QUOTE_ONLY_OWN_WORDS_MAX = 40`, `NEAR_DUPLICATE_RATIO = 0.85`, `NEAR_DUPLICATE_MIN_CHARS = 40`, `MAX_HANDLE_INSIGHTS = 6`.
* [x] **Task 1.4.2: Broadcast / Paired-Media / Duplicate-Copy / Velocity / Forum-Unlock Heuristics**
  - Velocity is measured as a ± 90 s radius around the target (not the span of the whole slice); forum-unlock reports the count of surrounding replies that are short or quote-only.
* [x] **Task 1.4.3: @handle Mention Classification (promotion vs. scam call-out vs. parroting)**
  - Per-mention type (`scam_callout` with negation scrubbing / `neutral_mention` for an addressed reply that opens with the handle / `promoted_contact` / `neutral_mention`) and provenance (`original` / `quoted` / `forwarded` / `relayed_copy` / `self_repost`).
  - Per-handle verdict precedence: `disputed_handle` > `community_scam_callout` > `coordinated_promotion` > `relayed_ad_copy` > `parroted_handle` > `single_promoted_contact` > `addressed_target_author` > `bot_contact_in_window` > `mention_only`.
  - Handles sharing identical promoter/relayer/warner sets (and target-author status) collapse into one commentary line.
* [x] **Task 1.4.4: Bot-Handle Context**
  - `…bot` handles are flagged with the role implied nearby (`escrow/guarantor`, `fallback contact`, `support/admin`, `storefront/order`, or *role not stated*) and a caveat that the bot may be benign or merely parroted — never asserted as actor infrastructure. A later mention can still supply the role if the first one did not. Bots advertised only by surrounding accounts share one line grouped per advertiser.
* [x] **Task 1.4.5: Offline Regression Harness**
  - Synthetic-window checks for every verdict, negation handling, thresholds, quote-only counting, grouping, bot-role upgrade, the `bot_contact_in_window` verdict and the sender cross-reference cases (`tests/test_context_signals.py`, 50 assertions); plus replay of an exported JSON record without API calls (`tests/replay_record.py`).
* [x] **Task 1.4.6: Sender Cross-Reference**
  - Author labels are resolved to handles (`Display (@name)` or bare forum usernames); each mentioned handle records `also_posts_in_window` (author label of the window message it sent, if any) and `is_target_author`. Commentary lines append *"is the TARGET AUTHOR's own handle"* (ranked first among equals, with the count of neutral addresses) or *"also posts in this window"*; a bare list of bot handles that are all active senders is described as a roster, not a contact. Console table rows carry `(TARGET AUTHOR)` / `(also posts in window)` tags.

---

## Phase 2: Cross-Platform Author Correlation & Reputation Augmentation

### Objective
Expand upon single-post evaluation by correlating the target author's handle or user ID across other underground forums and channels within a bounded temporal window, analyzing the sentiment and reputation of their posts in those environments, and feeding that historical context into the final post verdict.

### Milestone 2.1: Time-Framed Historical Retrieval
* [x] **Task 2.1.1: Time-Framing Bounded Queries (`[T - 14d, T]`)**
  - Given target post timestamp $T$, calculate temporal boundaries (default: $T - 14$ days, configurable via CLI `--lookback-days`).
  - Restrict historical post retrieval and corroboration queries to this window to avoid conflating stale historical events.
* [x] **Task 2.1.2: Multi-Platform Author Querying (Baseline Implemented)**
  - Search GTI DDW by `author.id` (Tier 1) and alias `author.name` (Tier 2), excluding the target post itself.
* [x] **Task 2.1.3: Deterministic Behavioral Metrics (Baseline Implemented)**
  - Compute platform dispersion, copypasta broadcast rate, and active window span via `--profile-author`.

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
