import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import requests

class GTIDDWClient:
    """Client for Google Threat Intelligence (GTI) Deep & Dark Web (DDW) API."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        self.api_key = api_key or os.getenv("GTI_APIKEY") or os.getenv("GTI_API_KEY") or os.getenv("VT_APIKEY")
        if not self.api_key:
            raise ValueError(
                "GTI API key not found. Set the GTI_APIKEY environment variable or pass api_key."
            )
        self.timeout = timeout
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key,
            "User-Agent": "GTI-DDW-Sentiment-Client/1.0"
        }
        self._author_cache: Dict[str, Dict[str, Any]] = {}

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform a GET request to the VirusTotal / GTI API with timeout and error handling."""
        url = f"{self.BASE_URL}{path}"
        response = requests.get(url, headers=self.headers, params=params, timeout=self.timeout)
        if response.status_code not in (200, 206):
            try:
                err_msg = response.json().get("error", {}).get("message", response.text)
            except Exception:
                err_msg = response.text
            raise RuntimeError(f"GTI API Error ({response.status_code}) for {path}: {err_msg}")
        return response.json()

    def get_communication(self, communication_id: str) -> Dict[str, Any]:
        """
        Fetch details of a single Dark Web Communication object.
        Explicitly requests 'relationships' so channel, thread, and author links are populated.
        """
        params = {"relationships": "communication_channel,conversation_thread,author,service"}
        res = self._get(f"/ddw_communications/{communication_id}", params=params)
        return res.get("data", {})

    def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        """Fetch Dark Web User Profile by ID (e.g. name, rank/titles, is_bot). Caches results."""
        if not user_id:
            return {}
        if user_id in self._author_cache:
            return self._author_cache[user_id]
        try:
            res = self._get(f"/ddw_user_profiles/{user_id}")
            profile = res.get("data", {}).get("attributes", {})
            self._author_cache[user_id] = profile
            return profile
        except Exception:
            return {"id": user_id}

    def search_communications_by_author(self, author_name: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for communications by author name."""
        params = {
            "filter": f'author.name:"{author_name}"',
            "limit": min(limit, 40)
        }
        res = self._get("/ddw_communications", params=params)
        return res.get("data", [])

    def search_communications_by_channel(self, channel_name: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Fetch sample communications from a specific channel name."""
        params = {
            "filter": f'communication_channel.name:"{channel_name}"',
            "limit": min(limit, 40)
        }
        res = self._get("/ddw_communications", params=params)
        return res.get("data", [])

    def get_channel_metadata(self, channel_id: str) -> Dict[str, Any]:
        """Fetch metadata for a Dark Web Communication Channel."""
        res = self._get(f"/ddw_communication_channels/{channel_id}")
        return res.get("data", {})

    def get_context_window(
        self,
        communication_id: str,
        window_size: int = 10
    ) -> Dict[str, Any]:
        """
        Fetch the target communication, resolve channel/thread metadata, and retrieve
        the chronological context (N previous messages and N next messages).
        Preserves both the original language text and English translation.
        """
        window_size = max(1, min(window_size, 40))
        target_data = self.get_communication(communication_id)
        if not target_data:
            raise ValueError(f"Communication ID '{communication_id}' not found.")

        target_attrs = target_data.get("attributes", {})
        relationships = target_data.get("relationships", {})
        target_ts = target_attrs.get("timestamp")

        comm_type = target_attrs.get("communication_type", "unknown")

        # Resolve author profile
        author_rel = relationships.get("author", {}).get("data", {})
        author_id = author_rel.get("id") if isinstance(author_rel, dict) else None
        target_author_profile = self.get_user_profile(author_id) if author_id else {}
        target_author_display = target_author_profile.get("name") or author_id or "Unknown"

        channel_id = None
        thread_id = None
        channel_metadata = {}

        if "communication_channel" in relationships and relationships["communication_channel"].get("data"):
            channel_id = relationships["communication_channel"]["data"].get("id")
        if "conversation_thread" in relationships and relationships["conversation_thread"].get("data"):
            thread_id = relationships["conversation_thread"]["data"].get("id")

        prev_items: List[Dict[str, Any]] = []
        next_items: List[Dict[str, Any]] = []
        retrieval_errors: List[str] = []

        params = {
            "limit": window_size,
            "attributes": "subject,content,content_translated,communication_type,timestamp",
            "relationships": "author"
        }

        # For forum posts, prioritize thread_id to get replies rather than unrelated board posts
        is_forum = (comm_type == "forum_post") or bool(thread_id and not channel_id)

        if is_forum and thread_id:
            prev_path = f"/ddw_conversation_threads/{thread_id}/previous_communications/{communication_id}"
            next_path = f"/ddw_conversation_threads/{thread_id}/next_communications/{communication_id}"

            if channel_id:
                try:
                    ch_data = self.get_channel_metadata(channel_id)
                    channel_metadata = ch_data.get("attributes", {})
                except Exception as e:
                    retrieval_errors.append(f"Channel metadata warning: {str(e)}")

        elif channel_id:
            prev_path = f"/ddw_communication_channels/{channel_id}/previous_communications/{communication_id}"
            next_path = f"/ddw_communication_channels/{channel_id}/next_communications/{communication_id}"

            try:
                ch_data = self.get_channel_metadata(channel_id)
                channel_metadata = ch_data.get("attributes", {})
            except Exception as e:
                retrieval_errors.append(f"Channel metadata warning: {str(e)}")
        else:
            prev_path = None
            next_path = None
            retrieval_errors.append(
                f"No parent channel or conversation thread found for communication {communication_id}. "
                "Context window cannot be fetched for this object type."
            )

        if prev_path:
            try:
                prev_res = self._get(prev_path, params=params)
                prev_items = prev_res.get("data", [])
            except Exception as e:
                retrieval_errors.append(f"Failed to fetch previous messages: {str(e)}")

        if next_path:
            try:
                next_res = self._get(next_path, params=params)
                next_items = next_res.get("data", [])
            except Exception as e:
                retrieval_errors.append(f"Failed to fetch subsequent messages: {str(e)}")

        def _format_time_delta(msg_ts: Optional[int]) -> str:
            if not msg_ts or not target_ts:
                return "N/A"
            diff = msg_ts - target_ts
            sign = "+" if diff >= 0 else "-"
            diff = abs(diff)
            hours, rem = divmod(diff, 3600)
            minutes, seconds = divmod(rem, 60)
            if hours >= 24:
                days = hours // 24
                return f"{sign}{days}d {hours % 24}h"
            return f"{sign}{hours:02d}:{minutes:02d}:{seconds:02d}"

        def _format_item(item: Dict[str, Any]) -> Dict[str, Any]:
            attrs = item.get("attributes", {})
            rels = item.get("relationships", {})
            msg_ts = attrs.get("timestamp")

            a_rel = rels.get("author", {}).get("data", {})
            a_id = a_rel.get("id") if isinstance(a_rel, dict) else None
            author_display = a_id or "Unknown"

            iso_time = (
                datetime.fromtimestamp(msg_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
                if msg_ts else "Unknown"
            )

            orig_text = (attrs.get("content") or "").strip()
            trans_text = (attrs.get("content_translated") or "").strip()
            display_text = trans_text or orig_text

            return {
                "id": item.get("id"),
                "subject": attrs.get("subject"),
                "text": display_text,
                "original_text": orig_text,
                "translated_text": trans_text,
                "timestamp": msg_ts,
                "timestamp_iso": iso_time,
                "relative_delta": _format_time_delta(msg_ts),
                "author": author_display
            }

        # Deduplicate and sort strictly in chronological order ascending
        formatted_prev = [
            _format_item(m) for m in prev_items if m.get("id") != communication_id
        ]
        formatted_prev.sort(key=lambda x: x.get("timestamp") or 0)

        formatted_next = [
            _format_item(m) for m in next_items if m.get("id") != communication_id
        ]
        formatted_next.sort(key=lambda x: x.get("timestamp") or 0)

        target_iso_time = (
            datetime.fromtimestamp(target_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
            if target_ts else "Unknown"
        )

        target_orig = (target_attrs.get("content") or "").strip()
        target_trans = (target_attrs.get("content_translated") or "").strip()
        target_display = target_trans or target_orig

        return {
            "target": {
                "id": communication_id,
                "type": comm_type,
                "subject": target_attrs.get("subject"),
                "text": target_display,
                "original_text": target_orig,
                "translated_text": target_trans,
                "timestamp": target_ts,
                "timestamp_iso": target_iso_time,
                "author": target_author_display,
                "author_profile": target_author_profile,
                "origin_url": target_attrs.get("origin_url")
            },
            "channel_or_thread": {
                "channel_id": channel_id,
                "thread_id": thread_id,
                "name": channel_metadata.get("name"),
                "description": channel_metadata.get("description"),
                "url": channel_metadata.get("url")
            },
            "context": {
                "previous_messages": formatted_prev,
                "next_messages": formatted_next
            },
            "retrieval_errors": retrieval_errors
        }
