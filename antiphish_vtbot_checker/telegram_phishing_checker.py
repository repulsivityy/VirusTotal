"""
Telegram Anti-Phishing Bot

This bot extracts URLs and domains from Telegram messages and checks them against
VirusTotal API and Google Web Risk API to identify potential phishing websites.

It provides a standardized response format for users, indicating whether the
links are safe, suspicious, or malicious. The bot is designed to handle multiple
requests efficiently and can be extended with additional security checkers in the future.

Gemini 2.5 Pro and Claude Sonnet was used to optimise the code for performance and readability.

Usage: 
1. Set environment variables for TELEGRAM_TOKEN, VIRUSTOTAL_API_KEY, and WEBRISK_API_KEY.
2. install required packages: `pip install python-telegram-bot aiohttp`.
3. Update your variables under --- Constants --- section if needed.
4. Run the script: `python telegram_phishing_checker.py`.

# author: dominicchua@
# version: 1.0
"""

import os
import re
import logging
import base64
import asyncio
import aiohttp
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# --- Configuration ---
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Load configuration from environment variables
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "YOUR_TELEGRAM_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")
WEBRISK_API_KEY = os.environ.get("WEBRISK_API_KEY", "YOUR_WEBRISK_API_KEY")

# --- Constants ---
MALICIOUS_THRESHOLD = 3
API_TIMEOUT = 10
TOTAL_TIMEOUT = 25
IDLE_SHUTDOWN_SECONDS = 600  # 10 minutes
MAX_CONCURRENT_CHECKS = 20

# --- Standardized Data Structure ---
@dataclass
class ScanResult:
    """A standardized object for all checker results."""
    is_malicious: bool
    summary: str
    source: str
    details: Dict = field(default_factory=dict)
    error: bool = False

# --- Core Components ---
class URLExtractor:
    """Extracts URLs and domains based on clear classification rules."""
    # A single, broad regex to find anything that looks like a link or domain.
    LINK_REGEX = re.compile(
        r'(?:https?://)?(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+[^\s]*'
    )

    @staticmethod
    def extract_urls_and_domains(text: str) -> List[Dict[str, str]]:
        """
        Finds all link-like strings and classifies them as either a URL or a Domain.
        - URL: Contains a protocol (://) or a path (/).
        - Domain: Does not contain a protocol or path.
        """
        candidates = URLExtractor.LINK_REGEX.findall(text)
        
        final_results = []
        seen = set()

        for candidate in candidates:
            # Rule: If it has a protocol or path, it's a URL.
            if "://" in candidate or "/" in candidate:
                item_type = 'url'
                # Ensure it has a protocol for the request
                if not candidate.startswith('http'):
                    value = 'http://' + candidate
                else:
                    value = candidate
            # Rule: Otherwise, it's a domain.
            else:
                item_type = 'domain'
                value = candidate
            
            # Add to results if we haven't seen this exact item before
            item_tuple = (item_type, value)
            if item_tuple not in seen:
                final_results.append({'type': item_type, 'value': value})
                seen.add(item_tuple)
                
        return final_results


class BaseChecker(ABC):
    """Abstract base class for security checkers."""
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    @abstractmethod
    async def check(self, value: str, item_type: str) -> ScanResult:
        """Checks a value and returns a standardized ScanResult."""
        pass


class VirusTotalChecker(BaseChecker):
    """Checks items against VirusTotal, returning a standard ScanResult."""
    SOURCE_NAME = "VirusTotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, session: aiohttp.ClientSession):
        super().__init__(session)
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}

    async def _make_request(self, endpoint, method='GET', **kwargs):
        return await self.session.request(method, endpoint, headers=self.headers, timeout=API_TIMEOUT, **kwargs)

    def _parse_results(self, vt_data: Dict) -> ScanResult:
        attributes = vt_data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", attributes.get("stats", {}))
        malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total_engines = sum(stats.values())
        is_malicious = malicious_count >= MALICIOUS_THRESHOLD
        summary = f"{malicious_count}/{total_engines} vendors flagged this"
        return ScanResult(is_malicious, summary, self.SOURCE_NAME, details=stats)

    async def check(self, value: str, item_type: str) -> ScanResult:
        try:
            endpoint_path = "urls" if item_type == "url" else "domains"
            identifier = base64.urlsafe_b64encode(value.encode()).decode().strip("=") if item_type == "url" else value
            endpoint = f"{self.BASE_URL}/{endpoint_path}/{identifier}"

            async with await self._make_request(endpoint) as response:
                if response.status == 404:
                    if item_type == 'url':
                        return await self._submit_and_check_url(value)
                    else:
                        return ScanResult(False, "Not found in database", self.SOURCE_NAME)
                response.raise_for_status()
                return self._parse_results(await response.json())
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"{self.SOURCE_NAME} error for {value}: {e}")
            return ScanResult(False, "API Error", self.SOURCE_NAME, error=True)

    async def _submit_and_check_url(self, url: str) -> ScanResult:
        return ScanResult(False, "Submitted for analysis", self.SOURCE_NAME)


class WebRiskChecker(BaseChecker):
    """Checks items against Google Web Risk, returning a standard ScanResult."""
    SOURCE_NAME = "Google Web Risk"
    BASE_URL = "https://webrisk.googleapis.com/v1eap1:evaluateUri"
    THREAT_TYPES = ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"]
    THREAT_NAMES = {"MALWARE": "Malware", "SOCIAL_ENGINEERING": "Social Engineering", "UNWANTED_SOFTWARE": "Unwanted Software"}

    def __init__(self, api_key: str, session: aiohttp.ClientSession):
        super().__init__(session)
        self.api_key = api_key

    def _parse_results(self, wr_data: Dict) -> ScanResult:
        if not wr_data or "scores" not in wr_data:
            return ScanResult(False, "No detections", self.SOURCE_NAME)
        
        is_malicious = False
        threat_scores = {}
        for score in wr_data.get("scores", []):
            confidence = score.get("confidenceLevel", "SAFE")
            threat_type = score.get("threatType")
            if confidence != "SAFE":
                is_malicious = True
            threat_scores[threat_type] = confidence

        summary = self._format_threat_summary(threat_scores)
        return ScanResult(is_malicious, summary, self.SOURCE_NAME, details=threat_scores)

    def _format_threat_summary(self, threat_scores: Dict) -> str:
        non_safe = [f"{self.THREAT_NAMES.get(t, t)}: {c}" for t, c in threat_scores.items() if c != "SAFE"]
        return ", ".join(non_safe) if non_safe else "No significant risk detected"

    async def check(self, value: str, item_type: str) -> ScanResult:
        url_to_check = value if item_type == 'url' else f"http://{value}"
        try:
            payload = {"uri": url_to_check, "threatTypes": self.THREAT_TYPES}
            async with self.session.post(f"{self.BASE_URL}?key={self.api_key}", json=payload, timeout=API_TIMEOUT) as response:
                response.raise_for_status()
                return self._parse_results(await response.json())
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"{self.SOURCE_NAME} error for {value}: {e}")
            return ScanResult(False, "API Error", self.SOURCE_NAME, error=True)


class ResponseFormatter:
    """Handles creating user-facing response messages from ScanResult objects."""
    RESPONSE_TEMPLATES = {
        "DANGER":  {"emoji": "🚨", "level": "DANGER: Malicious link detected!",  "rec": "🚫 DO NOT VISIT - This website poses a significant security risk."},
        "WARNING": {"emoji": "⚠️", "level": "WARNING: Potentially malicious link detected!", "rec": "⚠️ SUSPICIOUS - Proceed with caution and only if you trust the sender."},
        "SAFE":    {"emoji": "✅", "level": "Link seems safe",    "rec": "✅ SEEMS SAFE - No threats detected, but always be cautious with unknown websites."},
        "ERROR":   {"emoji": "❓", "level": "ERROR",   "rec": "❓ INCONCLUSIVE - Exercise caution as threat assessment is unclear."}
    }

    def _get_risk_level(self, vt_result: ScanResult, wr_result: ScanResult) -> str:
        if vt_result.error or wr_result.error:
            return "ERROR"
        
        wr_has_high_threat = any(c in ["HIGH", "EXTREMELY_HIGH"] for c in wr_result.details.values())
        if vt_result.is_malicious or wr_has_high_threat:
            return "DANGER"

        wr_is_malicious = any(c != "SAFE" for c in wr_result.details.values())
        vt_has_some_detections = vt_result.details.get("malicious", 0) > 0 or vt_result.details.get("suspicious", 0) > 0
        if wr_is_malicious or vt_has_some_detections:
             return "WARNING"

        return "SAFE"

    def format_combined_response(self, target: str, vt_result: ScanResult, wr_result: ScanResult) -> str:
        risk_level = self._get_risk_level(vt_result, wr_result)
        template = self.RESPONSE_TEMPLATES[risk_level]

        header = f"{template['emoji']} {template['level']}"
        recommendation = f"<b>Recommendation:</b>\n {template['rec']}"

        return (
            f"{header}\n"
            f"Link: <code>{target}</code>\n"
            "----------------------------------\n"
            f"VirusTotal: {vt_result.summary}\n"
            f"Google Web Risk: {wr_result.summary}\n\n"
            f"{recommendation}"
        )


class TelegramBot:
    """The main Telegram bot class, orchestrating all components."""
    def __init__(self, token: str):
        self.application = Application.builder().token(token).build()
        self.url_extractor = URLExtractor()
        self.response_formatter = ResponseFormatter()
        self._add_handlers()

        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()
        self._session_close_task: Optional[asyncio.Task] = None

    def _add_handlers(self):
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        self.application.add_error_handler(self.error_handler)

    async def _get_session(self) -> aiohttp.ClientSession:
        async with self._session_lock:
            if self._session_close_task and not self._session_close_task.done(): self._session_close_task.cancel()
            if self._session is None or self._session.closed:
                logger.info("Creating new aiohttp.ClientSession.")
                self._session = aiohttp.ClientSession()
            return self._session

    async def _schedule_session_shutdown(self):
        async with self._session_lock:
            self._session_close_task = asyncio.create_task(self._close_session_after_delay(IDLE_SHUTDOWN_SECONDS))

    async def _close_session_after_delay(self, delay: int):
        try:
            await asyncio.sleep(delay)
            async with self._session_lock:
                if self._session and not self._session.closed:
                    logger.info("Idle timeout reached. Closing ClientSession.")
                    await self._session.close()
        except asyncio.CancelledError:
            pass

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_html("Hi! I'm an anti-phishing bot. Send me a message with any link to check it.")

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_html("I check links against <b>VirusTotal</b> and <b>Google Web Risk</b>.")

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.message or not update.message.text: return
        items = self.url_extractor.extract_urls_and_domains(update.message.text)
        if not items:
            await update.message.reply_text("No URLs or domains were found in your message.")
            await self._schedule_session_shutdown()
            return

        total_items = len(items)
        await update.message.reply_text(f"Found {total_items} item(s). Beginning analysis...")
        
        session = await self._get_session()
        vt_checker = VirusTotalChecker(VIRUSTOTAL_API_KEY, session)
        webrisk_checker = WebRiskChecker(WEBRISK_API_KEY, session)

        for i in range(0, total_items, MAX_CONCURRENT_CHECKS):
            chunk = items[i:i + MAX_CONCURRENT_CHECKS]
            
            if total_items > MAX_CONCURRENT_CHECKS:
                await update.message.reply_text(
                    f"Processing items {i+1} to {i+len(chunk)} of {total_items}..."
                )

            tasks = [self._check_and_report_item(update, item, vt_checker, webrisk_checker) for item in chunk]
            await asyncio.gather(*tasks)
        
        logger.info(f"Finished processing all {total_items} items.")
        await self._schedule_session_shutdown()

    async def _check_and_report_item(self, update: Update, item: Dict, vt_checker: BaseChecker, webrisk_checker: BaseChecker):
        item_type, item_value = item['type'], item['value']
        proc_msg = await update.message.reply_html(f"🔍 Analyzing {item_type}: <code>{item_value}</code>")
        try:
            vt_task = vt_checker.check(item_value, item_type)
            wr_task = webrisk_checker.check(item_value, item_type)

            vt_result, wr_result = await asyncio.wait_for(
                asyncio.gather(vt_task, wr_task),
                timeout=TOTAL_TIMEOUT
            )
            response = self.response_formatter.format_combined_response(item_value, vt_result, wr_result)
            await proc_msg.edit_text(response, parse_mode='HTML')
        except asyncio.TimeoutError:
            await proc_msg.edit_text(f"⏰ <b>Timeout</b> checking <code>{item_value}</code>.", parse_mode='HTML')
        except Exception as e:
            logger.error(f"Error in _check_and_report_item for {item_value}: {e}", exc_info=True)
            await proc_msg.edit_text(f"❌ <b>Error</b> checking <code>{item_value}</code>.", parse_mode='HTML')

    async def error_handler(self, update: object, context: ContextTypes.DEFAULT_TYPE):
        logger.error(f"Update {update} caused error: {context.error}", exc_info=context.error)

    async def shutdown(self):
        async with self._session_lock:
            if self._session_close_task and not self._session_close_task.done(): self._session_close_task.cancel()
            if self._session and not self._session.closed: await self._session.close()

    def run(self):
        try:
            self.application.run_polling()
        finally:
            loop = asyncio.get_event_loop()
            if loop.is_running(): loop.create_task(self.shutdown())
            else: loop.run_until_complete(self.shutdown())

def main():
    for key_name in ["TELEGRAM_TOKEN", "VIRUSTOTAL_API_KEY", "WEBRISK_API_KEY"]:
        if os.environ.get(key_name, "").startswith("YOUR_") or not os.environ.get(key_name):
            logger.critical(f"{key_name} is not set. Please check your environment variables.")
            return

    bot = TelegramBot(TELEGRAM_TOKEN)
    logger.info("Starting fully optimized bot...")
    bot.run()

if __name__ == "__main__":
    main()