"""
Telegram Anti-Phishing Bot

This bot extracts URLs and domains from Telegram messages and checks them against
VirusTotal/Google Threat Intel API and Google Web Risk API to identify potential malicious websites.

It provides a standardized response format for users, indicating whether the
links are safe, suspicious, or malicious. 

It leverages a combination of VT detection ratio, GTI assessment and Web Risk's threat scores to provide a risk assessment.

Gemini 2.5 Pro and Claude Sonnet was used to optimise the code for performance and readability.

Usage: 
1. Set environment variables for TELEGRAM_TOKEN, VIRUSTOTAL_API_KEY, and WEBRISK_API_KEY.
2. install required packages: `pip install python-telegram-bot aiohttp`.
3. Update your variables under --- Constants --- section if needed.
4. Run the script: `python telegram_phishing_checker.py`.

# author: dominicchua@
# version: 1.2
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
IDLE_SHUTDOWN_SECONDS = 600
MAX_CONCURRENT_CHECKS = 20
VT_POLLING_SCHEDULE = [60, 45, 30, 30] 
TOTAL_POLLING_TIMEOUT = 240 # 4 minutes

# --- Standardized Data Structure ---
@dataclass
class ScanResult:
    """A standardized object for all checker results."""
    is_malicious: bool
    summary: str
    source: str
    details: Dict = field(default_factory=dict)
    error: bool = False
    is_pending: bool = False

# --- Core Components ---
class URLExtractor:
    """Extracts URLs and domains based on clear classification rules."""
    # --- REGEX UPDATED ---
    # This new regex recognizes that a host can be a domain name OR an IPv4 address.
    DOMAIN_NAME_PATTERN = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}"
    IPV4_PATTERN = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    HOST_PATTERN = f"(?:{DOMAIN_NAME_PATTERN}|{IPV4_PATTERN})"

    LINK_REGEX = re.compile(
        # Optional protocol, then host, then optional port, then optional path
        r'(?:https?://)?' + HOST_PATTERN + r'(?::\d+)?(?:[/?#][^\s]*)?',
        re.IGNORECASE
    )

    @staticmethod
    def extract_urls_and_domains(text: str) -> List[Dict[str, str]]:
        """
        Finds all link-like strings and classifies them as either a URL or a Domain.
        - URL: Contains a protocol (://), a port (:), or a path (/).
        - Domain: An IP or FQDN that does not meet the URL criteria.
        """
        candidates = URLExtractor.LINK_REGEX.findall(text)
        
        final_results = []
        seen = set()

        for candidate in candidates:
            # Rule: If it has a protocol, port, or path, it's a URL.
            if "://" in candidate or "/" in candidate or (":" in candidate and "://" not in candidate):
                item_type = 'url'
                value = 'http://' + candidate if not candidate.startswith('http') else candidate
            else:
                item_type = 'domain'
                value = candidate
            
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
        self.headers = {"x-apikey": self.api_key, "x-tool": "telegram-phishing-checker", "Accept": "application/json"}

    async def _make_request(self, endpoint, method='GET', **kwargs):
        return await self.session.request(method, endpoint, headers=self.headers, timeout=API_TIMEOUT, **kwargs)

    def _parse_results(self, vt_data: Dict) -> ScanResult:
        attributes = vt_data.get("data", {}).get("attributes", {})
        gti_assessment = attributes.get("gti_assessment")
        stats = attributes.get("last_analysis_stats", {})
        if not stats: return ScanResult(False, "No analysis data", self.SOURCE_NAME, error=True)
        malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total_engines = sum(stats.values())
        summary = f"{malicious_count}/{total_engines} vendors flagged this as malicious"
        details = stats
        if gti_assessment:
            gti_score = gti_assessment.get("threat_score", {}).get("value")
            details.update(gti_assessment)
            details['threat_score_value'] = gti_score
            is_malicious = details.get("verdict", {}).get("value") == "VERDICT_MALICIOUS"
        else:
            is_malicious = malicious_count >= MALICIOUS_THRESHOLD
        return ScanResult(is_malicious, summary, self.SOURCE_NAME, details=details)

    async def check(self, value: str, item_type: str) -> ScanResult:
        try:
            endpoint_path = "urls" if item_type == "url" else "domains"
            identifier = base64.urlsafe_b64encode(value.encode()).decode().strip("=") if item_type == "url" else value
            endpoint = f"{self.BASE_URL}/{endpoint_path}/{identifier}"
            async with await self._make_request(endpoint) as response:
                if response.status == 404:
                    return await self._submit_url(value) if item_type == 'url' else ScanResult(False, "Not found in database", self.SOURCE_NAME)
                response.raise_for_status()
                return self._parse_results(await response.json())
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"{self.SOURCE_NAME} error for {value}: {e}")
            return ScanResult(False, "API Error", self.SOURCE_NAME, error=True)

    async def _submit_url(self, url: str) -> ScanResult:
        try:
            submit_endpoint = f"{self.BASE_URL}/urls"
            payload = aiohttp.FormData(); payload.add_field('url', url)
            logger.info(f"URL not found. Submitting {url} for analysis.")
            async with await self._make_request(submit_endpoint, method='POST', data=payload) as response:
                if not response.ok: return ScanResult(False, "Failed to submit URL", self.SOURCE_NAME, error=True)
                analysis_id = (await response.json()).get("data", {}).get("id")
                if not analysis_id: return ScanResult(False, "Submission failed", self.SOURCE_NAME, error=True)
                return ScanResult(False, "⏳ Submitting for analysis...", self.SOURCE_NAME, details={"analysis_id": analysis_id}, is_pending=True)
        except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as e:
            logger.error(f"Error during URL submission for {url}: {e}")
            return ScanResult(False, "API Error during submission", self.SOURCE_NAME, error=True)
    
    async def poll_for_result(self, analysis_id: str) -> ScanResult:
        analysis_endpoint = f"{self.BASE_URL}/analyses/{analysis_id}"
        start_time = asyncio.get_running_loop().time()
        polling_intervals = VT_POLLING_SCHEDULE + [VT_POLLING_DEFAULT_INTERVAL] * 10
        for i, delay in enumerate(polling_intervals):
            if asyncio.get_running_loop().time() - start_time > TOTAL_POLLING_TIMEOUT:
                logger.warning(f"Total polling timeout reached for analysis ID {analysis_id}.")
                break
            logger.info(f"Polling VT analysis ID {analysis_id}. Waiting {delay}s... (Attempt {i+1})")
            await asyncio.sleep(delay)
            try:
                async with await self._make_request(analysis_endpoint) as response:
                    if response.ok:
                        analysis_data = await response.json()
                        status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                        if status == "completed":
                            logger.info(f"Analysis {analysis_id} complete.")
                            return self._parse_results(analysis_data)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.error(f"Polling error for analysis ID {analysis_id}: {e}")
        logger.warning(f"Polling finished without completion for analysis ID {analysis_id}.")
        return ScanResult(False, "Analysis timed out", self.SOURCE_NAME, error=True)


class WebRiskChecker(BaseChecker):
    SOURCE_NAME = "Google Web Risk"
    BASE_URL = "https://webrisk.googleapis.com/v1eap1:evaluateUri"
    THREAT_TYPES = ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"]
    THREAT_NAMES = {"MALWARE": "Malware", "SOCIAL_ENGINEERING": "Social Engineering", "UNWANTED_SOFTWARE": "Unwanted Software"}

    def __init__(self, api_key: str, session: aiohttp.ClientSession):
        super().__init__(session)
        self.api_key = api_key

    def _parse_results(self, wr_data: Dict) -> ScanResult:
        if not wr_data or "scores" not in wr_data: return ScanResult(False, "No detections", self.SOURCE_NAME)
        is_malicious = False; threat_scores = {}
        for score in wr_data.get("scores", []):
            confidence = score.get("confidenceLevel", "SAFE")
            if confidence != "SAFE": is_malicious = True
            threat_scores[score.get("threatType")] = confidence
        summary = self._format_threat_summary(threat_scores)
        return ScanResult(is_malicious, summary, self.SOURCE_NAME, details=threat_scores)

    def _format_threat_summary(self, threat_scores: Dict) -> str:
        non_safe = [f"{self.THREAT_NAMES.get(t, t)}: {c}" for t, c in threat_scores.items() if c != "SAFE"]
        return ", ".join(non_safe) if non_safe else "SAFE"

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
    RESPONSE_TEMPLATES = {
        "DANGER":  {"emoji": "🚨", "level": "DANGER: Malicious link detected!",  "rec": "🚫 DO NOT VISIT - This website poses a significant security risk."},
        "WARNING": {"emoji": "⚠️", "level": "WARNING: Potentially malicious link detected!", "rec": "⚠️ SUSPICIOUS - Proceed with caution and only if you trust the sender."},
        "SAFE":    {"emoji": "✅", "level": "Link seems safe",    "rec": "✅ SAFE - No threats detected, but always be cautious with unknown websites."},
        "ERROR":   {"emoji": "❓", "level": "ERROR",   "rec": "❓ INCONCLUSIVE - Exercise caution as threat assessment is unclear."}
    }

    def _get_risk_level(self, vt_result: ScanResult, wr_result: ScanResult) -> str:
        if vt_result.error or wr_result.error: return "ERROR"
        gti_score = vt_result.details.get("threat_score_value")
        gti_verdict = vt_result.details.get("verdict", {}).get("value")
        classic_vt_malicious_threshold = (vt_result.details.get("malicious", 0) + vt_result.details.get("suspicious", 0)) >= MALICIOUS_THRESHOLD
        wr_is_high_threat = any(c in ["HIGH", "EXTREMELY_HIGH"] for c in wr_result.details.values())
        if (gti_verdict == "VERDICT_MALICIOUS" or (gti_score is not None and gti_score > 60) or wr_is_high_threat or classic_vt_malicious_threshold):
            return "DANGER"
        classic_vt_is_clean = (vt_result.details.get("malicious", 0) + vt_result.details.get("suspicious", 0)) == 0
        wr_is_clean = all(c == "SAFE" for c in wr_result.details.values())
        if gti_verdict == "VERDICT_HARMLESS" or (classic_vt_is_clean and wr_is_clean):
            return "SAFE"
        return "WARNING"

    def format_combined_response(self, target: str, vt_result: ScanResult, wr_result: ScanResult, is_pending: bool = False) -> str:
        risk_level = self._get_risk_level(vt_result, wr_result)
        template = self.RESPONSE_TEMPLATES[risk_level]
        header = f"{template['emoji']} {template['level']}"
        recommendation = f"<b>Recommendation:</b>\n {template['rec']}"
        defanged_target = target.replace('.', '[.]').replace(':', '[:]')#.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
        gti_verdict_line = ""
        gti_verdict_raw = vt_result.details.get("verdict", {}).get("value")
        if gti_verdict_raw:
            display_verdict = gti_verdict_raw.replace("VERDICT_", "").capitalize()
            gti_verdict_line = f"Google TI Verdict: {display_verdict}"
        
        details_lines = [
            f"VirusTotal: {vt_result.summary}",
            gti_verdict_line,
            f"Google Web Risk: {wr_result.summary}"
        ]
        details_section = "\n".join(filter(None, details_lines))
        
        pending_text = "\n\n<i>⏳ Awaiting final analysis results from VirusTotal...</i>" if is_pending else ""
        
        return (f"{header}\n"f"Link: <code>{defanged_target}</code>\n""----------------------------------\n"f"{details_section}\n\n"f"{recommendation}{pending_text}")


class TelegramBot:
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
                await update.message.reply_text(f"Processing items {i+1} to {i+len(chunk)} of {total_items}...")
            tasks = [self._check_and_report_item(update, item, vt_checker, webrisk_checker) for item in chunk]
            await asyncio.gather(*tasks)
        logger.info(f"Finished processing all {total_items} items.")
        await self._schedule_session_shutdown()

    async def _check_and_report_item(self, update: Update, item: Dict, vt_checker: BaseChecker, webrisk_checker: BaseChecker):
        item_type, item_value = item['type'], item['value']
        proc_msg = await update.message.reply_html(f"🔍 Analyzing {item_type}: <code>{item_value.replace('.', '[.]')}</code>")
        try:
            vt_task = vt_checker.check(item_value, item_type)
            wr_task = webrisk_checker.check(item_value, item_type)
            vt_result, wr_result = await asyncio.wait_for(asyncio.gather(vt_task, wr_task), timeout=TOTAL_TIMEOUT)
            
            initial_risk_level = self.response_formatter._get_risk_level(vt_result, wr_result)
            should_poll = vt_result.is_pending and initial_risk_level == "SAFE"
            initial_response = self.response_formatter.format_combined_response(item_value, vt_result, wr_result, is_pending=should_poll)
            await proc_msg.edit_text(initial_response, parse_mode='HTML')
            if should_poll:
                analysis_id = vt_result.details.get("analysis_id")
                if analysis_id:
                    final_vt_result = await vt_checker.poll_for_result(analysis_id)
                    final_response = self.response_formatter.format_combined_response(item_value, final_vt_result, wr_result)
                    await proc_msg.edit_text(final_response, parse_mode='HTML')
        except asyncio.TimeoutError:
            await proc_msg.edit_text(f"⏰ <b>Timeout</b> checking <code>{item_value.replace('.', '[.]')}</code>.", parse_mode='HTML')
        except Exception as e:
            logger.error(f"Error in _check_and_report_item for {item_value}: {e}", exc_info=True)
            await proc_msg.edit_text(f"❌ <b>Error</b> checking <code>{item_value.replace('.', '[.]')}</code>.", parse_mode='HTML')

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
    required_vars = ["TELEGRAM_TOKEN", "VIRUSTOTAL_API_KEY", "WEBRISK_API_KEY"]
    if not all(os.environ.get(key) and not os.environ.get(key).startswith("YOUR_") for key in required_vars):
        logger.critical("One or more environment variables (TELEGRAM_TOKEN, VIRUSTOTAL_API_KEY, WEBRISK_API_KEY) are not set correctly.")
        return
    bot = TelegramBot(TELEGRAM_TOKEN)
    logger.info("Starting fully optimized bot...")
    bot.run()

if __name__ == "__main__":
    main()