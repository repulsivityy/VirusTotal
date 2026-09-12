# 🕵️ GTI Dark Web Contextual Sentiment & Threat Analyzer

A standalone threat intelligence tool that fetches Dark Web & Telegram communications from the **Google Threat Intelligence (GTI)** API, pulls a **$\pm 10$ message context window** around a target post, and uses **Gemini LLM reasoning** to evaluate threat intent, transaction progression, and community validation.

---

## 📌 Why Context Matters in Dark Web Chatter

Isolated dark web messages often mislead automated systems:
* A post claiming *"Selling access to Company X"* may look like an active breach.
* But the **10 subsequent chats** might say *"scammer"*, *"fake proof"*, or *"dm'ed / escrow?"*.
* Short messages like `"dm'ed"`, `"price?"`, `"+"` or `"vouch"` are **not discarded as noise**; they serve as critical indicators of whether a trade or compromise is actively progressing.

---

## 🚀 GTI DDW Endpoints Used

| Task | Endpoint |
| :--- | :--- |
| **Target Post Details** | `GET /ddw_communications/{communication_id}` |
| **Search by Author** | `GET /ddw_communications?filter=author.name:"<author>"` |
| **Channel Metadata (Bio/URL)**| `GET /ddw_communication_channels/{channel_id}` |
| **10 Preceding Chats (Channel)**| `GET /ddw_communication_channels/{channel_id}/previous_communications/{id}?limit=10` |
| **10 Subsequent Chats (Channel)**| `GET /ddw_communication_channels/{channel_id}/next_communications/{id}?limit=10` |
| **10 Preceding Posts (Forum)** | `GET /ddw_conversation_threads/{thread_id}/previous_communications/{id}?limit=10` |
| **10 Subsequent Posts (Forum)** | `GET /ddw_conversation_threads/{thread_id}/next_communications/{id}?limit=10` |

---

## 📦 Requirements & Installation

Only one third-party package is required:
```bash
pip install -r requirements.txt
```

### Environment Variables

Set your API keys:
```bash
# GTI / VirusTotal API Key
export GTI_APIKEY="your-gti-api-key"

# Gemini LLM API Key (used for CTI reasoning)
export GEMINI_API_KEY="your-gemini-api-key"
```

---

## 💻 Usage

### 1. Discover posts by a specific author
```bash
python main.py --author "threat_actor_handle"
```

### 2. Inspect a specific Telegram channel or forum
```bash
python main.py --channel "ransomware_news"
```

### 3. Analyze a target post with $\pm 10$ context window
```bash
python main.py --id "616a132d-f942-4165-b132-60eca4348c54" --window 10 --output analysis_record.json
```

---

## 🗄️ Output Schema (Ready for BigQuery / SQL)

The generated JSON file has the following structure for easy database streaming:

```json
{
  "communication_id": "616a132d-f942-4165-b132-60eca4348c54",
  "channel": {
    "channel_id": "f0fb347760e42d91...",
    "name": "Database Leaks & Access",
    "description": "Underground data trading channel",
    "url": "https://t.me/..."
  },
  "target_post": {
    "id": "...",
    "type": "messenger_message",
    "author": "actor_alias",
    "text": "Selling corporate VPN credentials for Bank ABC",
    "timestamp": 1720000000
  },
  "context_window": {
    "previous_count": 10,
    "next_count": 10,
    "previous_messages": [...],
    "next_messages": [...]
  },
  "analysis": {
    "channel_intelligence": {
      "primary_theme": "Initial Access Brokerage",
      "channel_credibility": "Medium"
    },
    "target_post_analysis": {
      "intent_category": "Initial_Access_Sale",
      "threat_severity": 4,
      "claimed_target_or_asset": "Bank ABC VPN credentials",
      "is_actionable_threat": true
    },
    "community_sentiment_and_reaction": {
      "reaction_status": "Negotiation_In_Progress",
      "buyer_interest_detected": true,
      "supporting_evidence_quotes": ["dm'ed", "check pm"],
      "reaction_narrative": "Multiple users immediately responded indicating interest in purchasing."
    },
    "executive_summary": "High risk initial access listing with active buyer negotiations occurring in the channel."
  }
}
```
