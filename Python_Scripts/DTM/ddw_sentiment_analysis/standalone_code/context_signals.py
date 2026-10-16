"""
context_signals.py — Deterministic behavioral commentary for CUTSIS context windows.

Every heuristic in this module runs purely over the bundle assembled by
``GTIDDWClient.get_context_window()`` (target post, +/- N surrounding messages, optional
forum thread root, optional author footprint). No network calls are made here, so every
signal is reproducible from the exported JSON record alone.

Thresholds are module-level constants so analysts can tune them without touching logic.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Tunable thresholds
# ---------------------------------------------------------------------------
MIN_CONTEXT_WINDOW = 7            # Minimum +/- window; broadcast / velocity thresholds are not meaningful below this
BROADCAST_MIN_HISTORY = 3         # Historical posts required before the author copypasta rate is trusted
BROADCAST_MIN_RATE = 0.5          # >= 50% identical text across the author's lookback history
PAIRED_MEDIA_MAX_GAP_SEC = 5      # Uncaptioned media within <= 5s of the target post
VELOCITY_RADIUS_SEC = 90          # Surrounding messages counted within +/- 90s of the target
VELOCITY_MIN_MESSAGES = 4
VELOCITY_MIN_SENDERS = 4
UNLOCK_REPLY_MAX_CHARS = 20       # Forum replies at or below this length on a non-root post
QUOTE_ONLY_OWN_WORDS_MAX = 40     # Own words after a quoted block at or below this = quote-only reply
NEAR_DUPLICATE_RATIO = 0.85       # SequenceMatcher ratio treated as "same text" (relay / parroting)
NEAR_DUPLICATE_MIN_CHARS = 40     # Shorter texts must match exactly to count as duplicates
MAX_HANDLE_INSIGHTS = 6           # Cap on handle-derived commentary lines per post
MEDIA_PLACEHOLDER = "[Media/Attachment — no text caption]"

# ---------------------------------------------------------------------------
# Lexicons (ASCII terms are matched on word boundaries; non-ASCII as substrings)
# ---------------------------------------------------------------------------
_HANDLE_RE = re.compile(r"(?<![\w.])@([A-Za-z][A-Za-z0-9_]{3,31})(?!\w)")

_SCAM_WORD_TERMS = [
    "scam", "scams", "scammer", "scammers", "scammed", "scamming", "ripper", "rippers", "ripped",
    "rip-off", "ripoff", "fake", "fakes", "faker", "fraud", "fraudster", "exit scam", "exitscam",
    "don't trust", "dont trust", "do not trust", "not trusted", "untrusted", "beware", "warning",
    "avoid", "stole", "stolen", "never pay", "blacklist", "blacklisted", "banned", "impersonator",
    "impersonating", "impersonates", "clone", "cloned", "not legit", "isn't legit", "is not legit",
    "liar", "report him", "report her", "reported",
]
_SCAM_SUBSTR_TERMS = [
    "кидала", "кидалово", "кинул", "скам", "скамер", "мошенник", "обман", "не платите", "не доверяйте",
    "забанен", "estafa", "estafador", "golpista", "arnaque", "arnaqueur", "betrug", "betrüger",
    "dolandırıcı", "penipu", "penipuan", "诈骗", "骗子",
]
_SCAM_NEGATIONS = [
    "no scam", "not a scam", "not scam", "non scam", "scam free", "scam-free", "zero scam", "anti scam",
    "anti-scam", "antiscam", "no fake", "not fake", "non fake", "no fakes", "no fraud", "not fraud",
    "no ripper", "not a ripper", "not ripper", "no rip", "без кидалова", "не скам", "не кидала",
    "sin estafa", "no estafa",
]
_CONTACT_WORD_TERMS = [
    "contact", "contacts", "dm", "dms", "pm", "pms", "write", "message", "msg", "inbox", "hit me", "hmu",
    "telegram", "tg", "order", "orders", "buy", "purchase", "sell", "sells", "selling", "escrow", "guarantor",
    "garant", "admin", "support", "owner", "seller", "vendor", "shop", "store", "channel", "bot", "deal", "deals",
    "price", "prices", "payment", "reach", "ping", "text me", "whatsapp", "jabber", "tox", "contacto", "escribe",
    "contato", "kontakt", "manager",
]
_CONTACT_SUBSTR_TERMS = [
    "связь", "контакт", "пиши", "писать", "заказ", "купить", "продавец", "поддержка", "админ",
    "менеджер", "гарант", "联系", "客服", "下单",
]
_CONTACT_CUE_EMOJI = ("👉", "📩", "📱", "✉", "💬", "📞", "📨", "🔗", "➡", "📲", "👤", "🆔")

_QUOTE_MARKER_RE = re.compile(
    r"(\bwrote:|\bsaid:|\bquote:|\boriginally posted by\b|\[quote\b|^\s*>\s|\bпишет:|\bписал\(а\):|\bescribió:)",
    re.IGNORECASE | re.MULTILINE,
)
_FORWARD_MARKER_RE = re.compile(
    r"(\bforwarded from\b|\bforwarded message\b|\bпереслано от\b|\breenviado de\b|\bweitergeleitet von\b)",
    re.IGNORECASE,
)

_BOT_ROLE_HINTS: List[Tuple[str, Tuple[str, ...]]] = [
    ("escrow/guarantor bot", ("escrow", "guarantor", "garant", "гарант", "middleman")),
    ("fallback contact bot", ("cannot send a message", "can't send a message", "if you cannot", "dm closed",
                              "if blocked", "if i don't answer", "if i dont answer", "two-way contact",
                              "two way contact", "双向联系")),
    ("support/admin bot", ("support", "admin", "help", "поддержка", "админ", "customer service", "客服")),
    ("storefront/order bot", ("shop", "store", "order", "buy", "catalog", "purchase", "магазин", "заказ",
                              "купить", "下单", "price")),
]

_MENTION_PRIORITY = {"scam_callout": 3, "promoted_contact": 2, "neutral_mention": 1}
_SEVERITY = {
    "disputed_handle": 7,
    "community_scam_callout": 6,
    "coordinated_promotion": 5,
    "relayed_ad_copy": 4,
    "parroted_handle": 3,
    "single_promoted_contact": 2,
    "addressed_target_author": 2,
    "bot_contact_in_window": 1,
    "mention_only": 0,
}


def _compile_words(terms: List[str]) -> List[re.Pattern]:
    return [re.compile(r"(?<!\w)" + re.escape(t) + r"(?!\w)", re.IGNORECASE) for t in terms]


_SCAM_WORD_RES = _compile_words(_SCAM_WORD_TERMS)
_CONTACT_WORD_RES = _compile_words(_CONTACT_WORD_TERMS)


# ---------------------------------------------------------------------------
# Small text helpers
# ---------------------------------------------------------------------------
def _has_any(text_lc: str, word_res: List[re.Pattern], substr_terms: List[str]) -> bool:
    return any(r.search(text_lc) for r in word_res) or any(t in text_lc for t in substr_terms)


def _scrub_negations(text_lc: str) -> str:
    for neg in _SCAM_NEGATIONS:
        text_lc = text_lc.replace(neg, " ")
    return text_lc


def _compress(text: str, limit: int = 100) -> str:
    flat = re.sub(r"\s+", " ", text or "").strip()
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _normalize(text: str) -> str:
    t = (text or "").lower()
    t = re.sub(r"https?://\S+|t\.me/\S+", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:600]


def _near_duplicate(a: str, b: str) -> bool:
    if not a or not b:
        return False
    if a == b:
        return True
    if min(len(a), len(b)) < NEAR_DUPLICATE_MIN_CHARS:
        return False
    sm = SequenceMatcher(None, a, b, autojunk=False)
    if sm.quick_ratio() < NEAR_DUPLICATE_RATIO:
        return False
    return sm.ratio() >= NEAR_DUPLICATE_RATIO


def _fmt_names(names: List[str], limit: int = 3) -> str:
    shown = ", ".join(f"'{n}'" for n in names[:limit])
    extra = len(names) - limit
    return shown + (f" +{extra} more" if extra > 0 else "")


def _is_quote_only(body: str) -> bool:
    """A reply that is a quoted block with (almost) no words of its own."""
    if not _QUOTE_MARKER_RE.search(body or ""):
        return False
    stripped = (body or "").rstrip()
    own_words = stripped.rsplit("\n\n", 1)[-1] if "\n\n" in stripped else ""
    if _QUOTE_MARKER_RE.search(own_words):
        own_words = ""
    return len(own_words.strip()) <= QUOTE_ONLY_OWN_WORDS_MAX


# ---------------------------------------------------------------------------
# Window assembly
# ---------------------------------------------------------------------------
def _build_window(
    target_obj: Dict[str, Any],
    prev_msgs: List[Dict[str, Any]],
    next_msgs: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    window: List[Dict[str, Any]] = []
    for source, is_target in ((prev_msgs, False), ([target_obj], True), (next_msgs, False)):
        for m in source:
            orig = (m.get("original_text") or "").strip()
            trans = (m.get("translated_text") or "").strip()
            disp = (m.get("text") or "").strip()
            texts: List[str] = []
            for t in (orig, trans, disp):
                if t and t != MEDIA_PLACEHOLDER and t not in texts:
                    texts.append(t)
            primary = orig if orig and orig != MEDIA_PLACEHOLDER else (disp or trans)
            window.append({
                "id": m.get("id"),
                "sender": (m.get("author") or "Unknown").strip(),
                "ts": m.get("timestamp"),
                "is_target": is_target,
                "texts": texts,
                "primary": primary,
                "norm": _normalize(primary),
            })
    return window


# ---------------------------------------------------------------------------
# Handle mention classification
# ---------------------------------------------------------------------------
def _classify_mention(text: str, start: int, end: int) -> Tuple[str, str]:
    """Classify one @handle occurrence from its local context. Returns (type, short_quote)."""
    a, b = max(0, start - 70), min(len(text), end + 50)
    local = text[a:b]
    local_lc = local.lower()
    quote = _compress(local)

    if _has_any(_scrub_negations(local_lc), _SCAM_WORD_RES, _SCAM_SUBSTR_TERMS):
        return "scam_callout", quote
    if len(text) <= 120 and _has_any(_scrub_negations(text.lower()), _SCAM_WORD_RES, _SCAM_SUBSTR_TERMS):
        return "scam_callout", quote

    # Addressed reply: the message opens with the handle and continues on the same line
    # ("@vendor_x price for 10k?") — the handle is the addressee, not a promoted contact.
    first_line_end = text.find("\n", end)
    first_line_end = len(text) if first_line_end == -1 else first_line_end
    if not text[:start].strip() and text[end:first_line_end].strip(" \t,:;-—–"):
        return "neutral_mention", quote

    if _has_any(local_lc, _CONTACT_WORD_RES, _CONTACT_SUBSTR_TERMS) or any(e in local for e in _CONTACT_CUE_EMOJI):
        return "promoted_contact", quote

    # Label layout: "<anything>: @handle" / "→ @handle" — the label word itself may be outside the lexicon.
    if text[:start].rstrip().endswith((":", "：", "→", "➜")):
        return "promoted_contact", quote

    # Contact-card layout: the handle sits (almost) alone on its own line.
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    if len(text[line_start:line_end].strip()) <= (end - start) + 12:
        return "promoted_contact", quote

    # Long advert with the handle in the closing third (typical contact block).
    if len(text) >= 200 and start >= int(len(text) * 0.66):
        return "promoted_contact", quote
    return "neutral_mention", quote


def _bot_role_hint(context_lc: str) -> Optional[str]:
    """Role stated near a bot handle, or None so a later mention can still supply one."""
    for role, cues in _BOT_ROLE_HINTS:
        if any(c in context_lc for c in cues):
            return role
    return None


def _extract_mentions(msg: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return {handle_lc: {type, quote, marker, raw}} for one message (best classification wins)."""
    results: Dict[str, Dict[str, Any]] = {}
    sender_lc = msg["sender"].lower()
    for text in msg["texts"]:
        quote_m = _QUOTE_MARKER_RE.search(text)
        fwd_m = _FORWARD_MARKER_RE.search(text)
        for m in _HANDLE_RE.finditer(text):
            raw = m.group(1)
            if raw.lower() in sender_lc:      # sender referencing their own handle
                continue
            handle = "@" + raw.lower()
            m_type, quote = _classify_mention(text, m.start(), m.end())
            marker: Optional[str] = None
            if quote_m and quote_m.start() < m.start():
                marker = "quoted"
            elif fwd_m:
                marker = "forwarded"
            prev = results.get(handle)
            if prev is None or _MENTION_PRIORITY[m_type] > _MENTION_PRIORITY[prev["type"]]:
                results[handle] = {
                    "type": m_type,
                    "quote": quote,
                    "marker": marker or (prev or {}).get("marker"),
                    "raw": raw,
                }
            elif marker and not prev.get("marker"):
                prev["marker"] = marker
    return results


def _new_handle_record(handle: str, raw: str) -> Dict[str, Any]:
    return {
        "handle": handle,
        "is_bot": raw.lower().endswith("bot"),
        "bot_role_hint": None,
        "in_target_post": False,
        "target_mention_type": None,
        "target_provenance": None,
        "also_posts_in_window": None,   # author label of a window message sent *by* this handle, if any
        "is_target_author": False,      # the handle resolves to the target post's author
        "assessment": "mention_only",
        "promoters": [],
        "relayers": [],
        "warners": [],
        "neutral_mentioners": [],
        "self_reposts": 0,
        "mentions": [],
    }


def _sender_handles(sender: str) -> List[str]:
    """Lower-case @handles an author label resolves to: '@name' tokens inside it, else the bare label itself."""
    found = ["@" + m.group(1).lower() for m in _HANDLE_RE.finditer(sender)]
    if found:
        return found
    bare = sender.strip()
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", bare):
        return ["@" + bare.lower()]
    return []


def _bot_caveat(recs: List[Dict[str, Any]]) -> str:
    bots = [r for r in recs if r["is_bot"]]
    if not bots:
        return ""
    described = ", ".join(
        f"{r['handle']} ({r.get('bot_role_hint') or 'role not stated in surrounding text'})" for r in bots
    )
    if len(bots) == 1:
        return (
            f" Note: {described} is a Telegram bot username (the 'bot' suffix is reserved for automated accounts) — "
            f"it may be the operator's storefront/escrow/support automation or a benign utility bot, so confirm its "
            f"function before treating it as actor infrastructure."
        )
    return (
        f" Note: {described} are Telegram bot usernames (the 'bot' suffix is reserved for automated accounts) — "
        f"they may be the operator's storefront/escrow/support automation or benign utility bots, so confirm their "
        f"function before treating them as actor infrastructure."
    )


def _assess_handle(rec: Dict[str, Any]) -> str:
    promoters, relayers, warners = rec["promoters"], rec["relayers"], rec["warners"]
    if warners and (promoters or relayers):
        return "disputed_handle"
    if warners:
        return "community_scam_callout"
    if len(promoters) >= 2:
        return "coordinated_promotion"
    if promoters and relayers:
        return "relayed_ad_copy"
    if len(relayers) >= 2 or (relayers and rec["in_target_post"] and rec.get("target_provenance") != "original"):
        return "parroted_handle"
    if rec["in_target_post"] and rec["target_mention_type"] == "promoted_contact":
        return "single_promoted_contact"
    if rec["is_target_author"] and rec["neutral_mentioners"]:
        return "addressed_target_author"
    if rec["is_bot"] and promoters and not rec["in_target_post"]:
        return "bot_contact_in_window"
    return "mention_only"


def _group_signature(rec: Dict[str, Any]) -> Tuple[Any, ...]:
    """Handles pushed / relayed / warned about by exactly the same accounts share one commentary line."""
    if rec["assessment"] == "bot_contact_in_window":
        return (rec["assessment"],)          # all surrounding-ad bots collapse into one line regardless of advertiser
    return (
        rec["assessment"],
        tuple(rec["promoters"]),
        tuple(rec["relayers"]),
        tuple(rec["warners"]),
        rec["in_target_post"],
        rec["is_target_author"],
    )


def _cross_reference_note(recs: List[Dict[str, Any]]) -> str:
    """Links a mentioned handle to the window itself: the target author, or another account posting in the window."""
    notes: List[str] = []
    owned = [r["handle"] for r in recs if r["is_target_author"]]
    if owned:
        verb = "are" if len(owned) > 1 else "is"
        note = f"{', '.join(owned)} {verb} the TARGET AUTHOR's own handle — this bears directly on the post under analysis."
        addressed = sorted({n for r in recs if r["is_target_author"] for n in r["neutral_mentioners"]})
        if addressed:
            note += f" It is also addressed neutrally by {len(addressed)} other account(s) ({_fmt_names(addressed)})."
        notes.append(note)
    active = [r for r in recs if r["also_posts_in_window"] and not r["is_target_author"]]
    if active:
        verb = "also post" if len(active) > 1 else "also posts"
        who = ", ".join(f"{r['handle']} (as '{r['also_posts_in_window']}')" for r in active)
        notes.append(f"{who} {verb} in this window — read that message with this in mind.")
    return (" " + " ".join(notes)) if notes else ""


def _describe_bot_contacts(recs: List[Dict[str, Any]]) -> str:
    """One line for all `…bot` handles advertised only by surrounding accounts, grouped per advertiser."""
    by_advertiser: Dict[str, List[Dict[str, Any]]] = {}
    for r in recs:
        by_advertiser.setdefault(r["promoters"][0], []).append(r)

    parts: List[str] = []
    for advertiser, group in by_advertiser.items():
        roles = {r.get("bot_role_hint") or "role not stated" for r in group}
        if len(roles) == 1:
            handles = f"{', '.join(r['handle'] for r in group)} ({roles.pop()})"
        else:
            handles = ", ".join(f"{r['handle']} ({r.get('bot_role_hint') or 'role not stated'})" for r in group)
        active = [r for r in group if r["also_posts_in_window"]]
        owned = [r["handle"] for r in group if r["is_target_author"]]
        extra: List[str] = []
        if owned:
            extra.append(f"{', '.join(owned)} is the TARGET AUTHOR's own handle")
        if active and len(active) == len(group) and len(group) > 1:
            extra.append(
                f"all {len(group)} also post in this window — a roster of accounts active here rather than a contact"
            )
        elif active:
            verb = "also post" if len(active) > 1 else "also posts"
            extra.append(f"{', '.join(r['handle'] for r in active)} {verb} in this window")
        parts.append(f"by '{advertiser}': {handles}" + (f" [{'; '.join(extra)}]" if extra else ""))

    plural = len(recs) > 1
    s = "s" if plural else ""
    subject = "each may be its" if plural else "it may be that"
    tail = "none of this says anything" if plural else "this says nothing"
    return (
        f"Bot handle{s} advertised in surrounding messages, not in the target post — {'; '.join(parts)}. "
        f"The 'bot' suffix is reserved for automated accounts; {subject} advertiser's storefront/escrow/support "
        f"automation or a benign utility bot, and {tail} about the target author unless the same handle recurs."
    )


def _describe_group(assessment: str, recs: List[Dict[str, Any]]) -> Optional[str]:
    rep = recs[0]
    h = ", ".join(r["handle"] for r in recs)
    plural = len(recs) > 1
    s = "s" if plural else ""
    is_are = "are" if plural else "is"
    promoters, relayers, warners = rep["promoters"], rep["relayers"], rep["warners"]
    warn_quote = next((m["quote"] for r in recs for m in r["mentions"] if m["type"] == "scam_callout"), "")
    bot_note = _bot_caveat(recs)
    xref_note = _cross_reference_note(recs)

    if assessment == "disputed_handle":
        return (
            f"Disputed handle{s}: {h} {is_are} promoted by {_fmt_names(promoters + relayers)} but called out as a "
            f"scam/ripper by {_fmt_names(warners)} (\"{warn_quote}\") — treat the promotion as contested, not as a vouch."
            + xref_note + bot_note
        )
    if assessment == "community_scam_callout":
        return (
            f"Scam call-out, not a promotion: {len(warners)} account(s) ({_fmt_names(warners)}) warn against {h} "
            f"(\"{warn_quote}\")." + xref_note + bot_note
        )
    if assessment == "coordinated_promotion":
        return (
            f"Coordinated handle promotion: {len(promoters)} distinct accounts ({_fmt_names(promoters)}) push the same "
            f"contact{s} {h} in their own wording — consistent with multi-account shilling; confirm they are not one "
            f"operator before reading this as independent endorsement." + xref_note + bot_note
        )
    if assessment == "relayed_ad_copy":
        return (
            f"Relayed ad copy: {h} {is_are} promoted by '{promoters[0]}' and re-posted/forwarded near-verbatim by "
            f"{_fmt_names(relayers)} — the later mentions parrot prior content rather than add independent endorsement."
            + xref_note + bot_note
        )
    if assessment == "parroted_handle":
        provenance = sorted({m["provenance"] for r in recs for m in r["mentions"] if m["provenance"] != "original"})
        where = "in the target post " if rep["in_target_post"] else ""
        return (
            f"Parroted handle{s}: {h} appear{'' if plural else 's'} {where}only inside quoted/forwarded/duplicated "
            f"content ({_fmt_names(relayers)}; provenance: {', '.join(provenance)}) — repeated prior information, "
            f"not an original claim or endorsement." + xref_note + bot_note
        )
    if assessment == "single_promoted_contact":
        return (
            f"Contact handle{s} in target post: {h} — promoted only by the target author within the window "
            f"(no corroborating or dissenting mentions)." + xref_note + bot_note
        )
    if assessment == "addressed_target_author":
        addressed = sorted({n for r in recs for n in r["neutral_mentioners"]})
        reply_quote = next((m["quote"] for r in recs for m in r["mentions"] if m["type"] == "neutral_mention"), "")
        return (
            f"Target author addressed directly: {len(addressed)} account(s) ({_fmt_names(addressed)}) reply to or "
            f"mention {h} without promoting or disputing it (\"{reply_quote}\") — engagement with the post, "
            f"not endorsement." + bot_note
        )
    if assessment == "bot_contact_in_window":
        return _describe_bot_contacts(recs)
    return None


def _analyze_handles(window: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    per_msg = [_extract_mentions(msg) for msg in window]
    records: Dict[str, Dict[str, Any]] = {}

    for i, msg in enumerate(window):
        for handle, info in per_msg[i].items():
            rec = records.setdefault(handle, _new_handle_record(handle, info["raw"]))
            provenance = info["marker"] or "original"
            if provenance == "original":
                for j in range(i):
                    if handle in per_msg[j] and _near_duplicate(window[j]["norm"], msg["norm"]):
                        provenance = "self_repost" if window[j]["sender"] == msg["sender"] else "relayed_copy"
                        break

            rec["mentions"].append({
                "sender": msg["sender"],
                "message_id": msg["id"],
                "is_target": msg["is_target"],
                "type": info["type"],
                "provenance": provenance,
                "quote": info["quote"],
            })
            if msg["is_target"]:
                rec["in_target_post"] = True
                rec["target_mention_type"] = info["type"]
                rec["target_provenance"] = provenance
            if rec["is_bot"] and not rec["bot_role_hint"]:
                rec["bot_role_hint"] = _bot_role_hint(info["quote"].lower())

            if provenance == "self_repost":
                rec["self_reposts"] += 1
                continue
            if info["type"] == "scam_callout":
                bucket = "warners"
            elif info["type"] == "promoted_contact":
                bucket = "promoters" if provenance == "original" else "relayers"
            else:
                bucket = "neutral_mentioners"
            if msg["sender"] not in rec[bucket]:
                rec[bucket].append(msg["sender"])

    # Cross-reference mentioned handles against the accounts that actually post in this window.
    sender_index: Dict[str, str] = {}
    target_handles: set = set()
    for msg in window:
        for h in _sender_handles(msg["sender"]):
            sender_index.setdefault(h, msg["sender"])
            if msg["is_target"]:
                target_handles.add(h)

    groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = {}
    for rec in records.values():
        rec["also_posts_in_window"] = sender_index.get(rec["handle"])
        rec["is_target_author"] = rec["handle"] in target_handles
        rec["assessment"] = _assess_handle(rec)
        rec["mentions"] = rec["mentions"][:6]
        if rec["assessment"] != "mention_only":
            groups.setdefault(_group_signature(rec), []).append(rec)

    def _rank(assessment: str, about_target_author: bool) -> float:
        return _SEVERITY[assessment] + (0.5 if about_target_author else 0.0)

    scored: List[Tuple[float, str]] = []
    for signature, recs in groups.items():
        line = _describe_group(signature[0], recs)
        if line:
            scored.append((_rank(signature[0], any(r["is_target_author"] for r in recs)), line))

    scored.sort(key=lambda x: -x[0])
    ordered = sorted(records.values(), key=lambda r: -_rank(r["assessment"], r["is_target_author"]))
    return ordered, [line for _, line in scored]


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------
def analyze_context_signals(
    target_obj: Dict[str, Any],
    prev_msgs: List[Dict[str, Any]],
    next_msgs: List[Dict[str, Any]],
    thread_root: Optional[Dict[str, Any]] = None,
    author_footprint: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Compute deterministic behavioral signals for a context window.

    Returns {"insights": List[str], "handle_mentions": List[Dict]}.
    """
    insights: List[str] = []
    target_ts = target_obj.get("timestamp")
    comm_type = target_obj.get("type")
    target_author = (target_obj.get("author") or "Unknown").strip()

    window = _build_window(target_obj, prev_msgs or [], next_msgs or [])
    tgt = next(m for m in window if m["is_target"])

    # 1. Author broadcast pattern (requires --profile-author footprint)
    if author_footprint:
        hist_n = int(author_footprint.get("total_historical_posts_retrieved") or 0)
        rate = float(author_footprint.get("copypasta_broadcast_rate") or 0.0)
        if hist_n >= BROADCAST_MIN_HISTORY and rate >= BROADCAST_MIN_RATE:
            plats = author_footprint.get("platforms_observed") or []
            plat_str = f" across {len(plats)} platform(s) ({', '.join(plats[:4])})" if plats else ""
            insights.append(
                f"Automated broadcast pattern: {int(rate * 100)}% of the author's {hist_n} historical posts in the "
                f"lookback window are identical text{plat_str} — automated cross-channel spam rather than a one-off post."
            )

    # 2. Paired media banner + caption drop (immediately adjacent message only)
    adjacent: List[Tuple[str, Dict[str, Any]]] = []
    if prev_msgs:
        adjacent.append(("preceding", prev_msgs[-1]))
    if next_msgs:
        adjacent.append(("subsequent", next_msgs[0]))
    for direction, adj in adjacent:
        adj_ts = adj.get("timestamp")
        if (adj.get("text") or "").strip() != MEDIA_PLACEHOLDER or target_ts is None or adj_ts is None:
            continue
        gap = abs(int(target_ts) - int(adj_ts))
        if gap <= PAIRED_MEDIA_MAX_GAP_SEC:
            adj_sender = (adj.get("author") or "Unknown").strip()
            who = (
                f"same sender '{adj_sender}'" if adj_sender == target_author
                else f"companion account '{adj_sender}' alongside target author '{target_author}'"
            )
            insights.append(
                f"Two-part promo drop: {direction} uncaptioned media attachment posted {gap}s from the target ({who}) "
                f"— banner + ad-copy pairing typical of automated promotion."
            )
            break

    # 3. Near-verbatim copies of the target text inside the window
    if len(tgt["norm"]) >= NEAR_DUPLICATE_MIN_CHARS:
        other_senders: List[str] = []
        same_sender_copies = 0
        for m in window:
            if m is tgt or not _near_duplicate(tgt["norm"], m["norm"]):
                continue
            if m["sender"] == tgt["sender"]:
                same_sender_copies += 1
            elif m["sender"] not in other_senders:
                other_senders.append(m["sender"])
        if other_senders:
            insights.append(
                f"Duplicate ad copy in window: the target text also appears near-verbatim from {len(other_senders)} "
                f"other account(s) ({_fmt_names(other_senders)}) — relayed/copypasta content rather than an organic post."
            )
        if same_sender_copies:
            insights.append(
                f"Repeat broadcast: the target author re-posted near-identical text {same_sender_copies} more time(s) "
                f"within the window."
            )

    # 4. @handle mentions: promoted contact vs scam call-out, provenance, bot caveat
    handle_records, handle_lines = _analyze_handles(window)
    insights.extend(handle_lines[:MAX_HANDLE_INSIGHTS])

    # 5. High-velocity interleaved stream (messenger channels)
    if comm_type == "messenger_message" and target_ts is not None:
        near = [
            m for m in window
            if not m["is_target"] and m["ts"] is not None and abs(int(m["ts"]) - int(target_ts)) <= VELOCITY_RADIUS_SEC
        ]
        senders = {m["sender"] for m in near}
        if len(near) >= VELOCITY_MIN_MESSAGES and len(senders) >= VELOCITY_MIN_SENDERS:
            stamps = [int(m["ts"]) for m in near] + [int(target_ts)]
            insights.append(
                f"High-velocity broadcast stream: {len(near)} surrounding messages from {len(senders)} distinct senders "
                f"within ±{VELOCITY_RADIUS_SEC}s of the target (span {max(stamps) - min(stamps)}s) — adjacent messages "
                f"are interleaved promos, not replies to the target."
            )

    # 6. Forum unlock chatter on an established thread
    if comm_type == "forum_post" and thread_root and not thread_root.get("is_target_post"):
        t_text = tgt["primary"]
        if 0 < len(t_text) <= UNLOCK_REPLY_MAX_CHARS:
            total = short_or_quote = 0
            for m in window:
                if m["is_target"]:
                    continue
                total += 1
                if len(m["primary"]) <= UNLOCK_REPLY_MAX_CHARS or _is_quote_only(m["primary"]):
                    short_or_quote += 1
            extra = f"; {short_or_quote} of {total} surrounding replies are likewise short or quote-only" if total else ""
            insights.append(
                f"Forum unlock chatter: short {len(t_text)}-char reply ('{t_text}') on an established thread "
                f"({thread_root.get('prior_posts_count', '?')} prior posts){extra} — reply-to-unlock filler rather than "
                f"technical vetting."
            )

    return {"insights": insights, "handle_mentions": handle_records}


def compute_context_insights(
    target_obj: Dict[str, Any],
    prev_msgs: List[Dict[str, Any]],
    next_msgs: List[Dict[str, Any]],
    thread_root: Optional[Dict[str, Any]] = None,
    author_footprint: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Commentary-only convenience wrapper around analyze_context_signals()."""
    return analyze_context_signals(target_obj, prev_msgs, next_msgs, thread_root, author_footprint)["insights"]
