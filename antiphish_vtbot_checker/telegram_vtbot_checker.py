"""
Telegram Anti-Phishing Bot

This bot extracts URLs and domains from Telegram messages and checks them against VirusTotal API
to identify potential phishing websites, using direct report fetching instead of submission.
"""

import os
import re
import logging
import requests
import urllib.parse
import base64
from typing import Optional, List, Tuple, Dict
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Configuration
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "YOUR_TELEGRAM_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")
MALICIOUS_THRESHOLD = 2  # Number of detections to consider URL as malicious


class URLExtractor:
    """Extract URLs and domains from text messages."""
    
    @staticmethod
    def extract_urls_and_domains(text: str) -> List[Dict[str, str]]:
        """
        Extract URLs and domains from the given text.
        
        Args:
            text (str): The text message to extract URLs and domains from
            
        Returns:
            List[Dict[str, str]]: A list of extracted URLs and domains with their types
                                 [{'type': 'url', 'value': 'http://example.com'}, 
                                  {'type': 'domain', 'value': 'example.org'}]
        """
        results = []
        
        # URL regex pattern (with protocol)
        # More comprehensive pattern to catch most URLs
        #### Original Regex - ####
        #url_pattern = r'(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})'
        url_pattern = r'(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}[^\s]*|(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}[^\s]*)'
        urls = re.findall(url_pattern, text)
        
        for url in urls:
            # Ensure URL has protocol prefix
            if not url.startswith('http'):
                if url.startswith('www.'):
                    url = 'http://' + url
                else:
                    url = 'http://' + url
            results.append({'type': 'url', 'value': url})
        
        # Domain regex pattern (without protocol)
        # This matches common TLDs but might need refinement based on needs
        domain_pattern = r'(?<!\w)(?!www\.)(?!http)(?!https)([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.)+(?:com|org|net|gov|edu|io|co|info|biz|me|xyz|app|dev|ai|cloud|site)(?!\w)'
        domains = re.findall(domain_pattern, text)
        
        # Filter out domains that were already matched as part of URLs
        for domain in domains:
            is_in_url = False
            for result in results:
                if domain in result['value']:
                    is_in_url = True
                    break
            
            if not is_in_url:
                results.append({'type': 'domain', 'value': domain})
        
        return results


class VirusTotalChecker:
    """Check URLs and domains against VirusTotal API."""
    
    def __init__(self, api_key: str):
        """
        Initialize the VirusTotal checker.
        
        Args:
            api_key (str): VirusTotal API key
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
    
    def check_url(self, url: str) -> Tuple[bool, int, int]:
        """
        Check if a URL is potentially malicious using VirusTotal's direct report endpoint.
        
        Args:
            url (str): The URL to check
            
        Returns:
            Tuple[bool, int, int]: (is_malicious, malicious_count, total_engines)
        """
        try:
            # URL identification in VirusTotal API requires base64 of the URL
            # First ensure URL has proper encoding
            url = url.strip()
            
            # Using the URL id API - needs base64 encoding of the URL
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            endpoint = f"{self.base_url}/urls/{url_id}"
            logger.info(f"Checking URL with endpoint: {endpoint}")
            
            response = requests.get(endpoint, headers=self.headers)
            # Log response status and first part of content for debugging
            logger.info(f"Response status: {response.status_code}")
            logger.info(f"Response preview: {response.text[:200]}...")
            
            response.raise_for_status()
            
            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            
            malicious_count = last_analysis_stats.get("malicious", 0)
            suspicious_count = last_analysis_stats.get("suspicious", 0)
            total_engines = sum(last_analysis_stats.values())
            
            # Consider both malicious and suspicious counts
            is_malicious = (malicious_count + suspicious_count) >= MALICIOUS_THRESHOLD
            return is_malicious, malicious_count, total_engines
            
        except requests.RequestException as e:
            logger.error(f"Error checking URL with VirusTotal: {e}")
            
            # Check if we got a 404 which means the URL hasn't been scanned yet
            if hasattr(e, 'response') and e.response is not None and e.response.status_code == 404:
                logger.info(f"URL {url} not found in VirusTotal database. Attempting to submit...")
                return self.submit_and_check_url(url)
            
            # Try to get more detailed error information
            error_message = "Unknown error"
            try:
                if hasattr(e, 'response') and e.response is not None:
                    error_data = e.response.json()
                    error_message = error_data.get("error", {}).get("message", "Unknown error")
            except:
                pass
            
            logger.error(f"VirusTotal API error details: {error_message}")
            return False, 0, 0
    
    def submit_and_check_url(self, url: str) -> Tuple[bool, int, int]:
        """
        Submit a URL to VirusTotal and check the results.
        Only used when a URL isn't already in the database.
        
        Args:
            url (str): The URL to submit and check
            
        Returns:
            Tuple[bool, int, int]: (is_malicious, malicious_count, total_engines)
        """
        try:
            # Submit URL for scanning
            submit_endpoint = f"{self.base_url}/urls"
            data = {"url": url}
            response = requests.post(submit_endpoint, headers=self.headers, data=data)
            response.raise_for_status()
            
            # Extract analysis ID from response
            result = response.json()
            analysis_id = result.get("data", {}).get("id")
            
            if not analysis_id:
                logger.error("No analysis ID returned after URL submission")
                return False, 0, 0
            
            # Check analysis status
            analysis_endpoint = f"{self.base_url}/analyses/{analysis_id}"
            response = requests.get(analysis_endpoint, headers=self.headers)
            response.raise_for_status()
            
            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})
            stats = attributes.get("stats", {})
            
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            total_engines = sum(stats.values()) if stats else 0
            
            # Consider both malicious and suspicious counts
            is_malicious = (malicious_count + suspicious_count) >= MALICIOUS_THRESHOLD
            return is_malicious, malicious_count, total_engines
            
        except requests.RequestException as e:
            logger.error(f"Error submitting URL to VirusTotal: {e}")
            return False, 0, 0
    
    def check_domain(self, domain: str) -> Tuple[bool, int, int]:
        """
        Check if a domain is potentially malicious using VirusTotal.
        
        Args:
            domain (str): The domain to check
            
        Returns:
            Tuple[bool, int, int]: (is_malicious, malicious_count, total_engines)
        """
        try:
            # Make sure domain is clean
            domain = domain.strip()
            
            endpoint = f"{self.base_url}/domains/{domain}"
            logger.info(f"Checking domain with endpoint: {endpoint}")
            
            response = requests.get(endpoint, headers=self.headers)
            # Log response status for debugging
            logger.info(f"Response status: {response.status_code}")
            logger.info(f"Response preview: {response.text[:200]}...")
            
            response.raise_for_status()
            
            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            
            malicious_count = last_analysis_stats.get("malicious", 0)
            suspicious_count = last_analysis_stats.get("suspicious", 0)
            total_engines = sum(last_analysis_stats.values())
            
            # Consider both malicious and suspicious counts
            is_malicious = (malicious_count + suspicious_count) >= MALICIOUS_THRESHOLD
            return is_malicious, malicious_count, total_engines
            
        except requests.RequestException as e:
            logger.error(f"Error checking domain with VirusTotal: {e}")
            
            # Try to get more detailed error information
            error_message = "Unknown error"
            try:
                if hasattr(e, 'response') and e.response is not None:
                    error_data = e.response.json()
                    error_message = error_data.get("error", {}).get("message", "Unknown error")
            except:
                pass
            
            logger.error(f"VirusTotal API error details: {error_message}")
            return False, 0, 0


class TelegramBot:
    """Telegram bot implementation."""
    
    def __init__(self, token: str, vt_checker: VirusTotalChecker):
        """
        Initialize the Telegram bot.
        
        Args:
            token (str): Telegram bot token
            vt_checker (VirusTotalChecker): VirusTotal checker instance
        """
        self.token = token
        self.vt_checker = vt_checker
        self.url_extractor = URLExtractor()
        self.application = Application.builder().token(token).build()
        
        # Add handlers
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        
        # Add error handler
        self.application.add_error_handler(self.error_handler)
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """
        Handle the /start command.
        
        Args:
            update (Update): The update object
            context (ContextTypes.DEFAULT_TYPE): The context object
        """
        user = update.effective_user
        await update.message.reply_text(
            f"Hi {user.first_name}! I'm an anti-phishing bot. Send me a message containing a URL or domain, "
            f"and I'll check if it's a potential phishing website.\n\n"
            f"Type /help for more information."
        )
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """
        Handle the /help command.
        
        Args:
            update (Update): The update object
            context (ContextTypes.DEFAULT_TYPE): The context object
        """
        await update.message.reply_text(
            "I can help you identify potential phishing websites.\n\n"
            "Just send me a message containing a URL (http://example.com) or domain (example.com), "
            "and I'll check it against VirusTotal's database.\n\n"
            "Commands:\n"
            "/start - Start the bot\n"
            "/help - Show this help message"
        )
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """
        Handle incoming messages.
        
        Args:
            update (Update): The update object
            context (ContextTypes.DEFAULT_TYPE): The context object
        """
        message_text = update.message.text
        items = self.url_extractor.extract_urls_and_domains(message_text)
        
        if not items:
            await update.message.reply_text("No URLs or domains found in your message.")
            return
        
        await update.message.reply_text(f"Found {len(items)} URL(s)/Domain(s). Checking against VirusTotal...")
        
        for item in items:
            if item['type'] == 'url':
                await self.check_and_report_url(update, item['value'])
            else:  # domain
                await self.check_and_report_domain(update, item['value'])
    
    async def check_and_report_url(self, update: Update, url: str) -> None:
        """
        Check a URL against VirusTotal and report results.
        
        Args:
            update (Update): The update object
            url (str): The URL to check
        """
        try:
            is_malicious, malicious_count, total_engines = self.vt_checker.check_url(url)
            
            if is_malicious:
                await update.message.reply_text(
                    f"⚠️ WARNING: Potentially malicious URL detected!\n\n"
                    f"URL: {url}\n"
                    f"Detections: {malicious_count}/{total_engines} security vendors flagged this URL as malicious.\n\n"
                    f"Recommendation: Do not visit this website."
                )
            else:
                await update.message.reply_text(
                    f"✅ URL seems safe: {url}\n"
                    f"Detections: {malicious_count}/{total_engines} security vendors flagged this URL.\n\n"
                    f"Note: Always be cautious when visiting unknown websites."
                )
        except Exception as e:
            logger.error(f"Error checking URL {url}: {e}")
            await update.message.reply_text(
                f"Error checking URL: {url}\n"
                f"Please try again later or report this issue to the bot administrator."
            )
    
    async def check_and_report_domain(self, update: Update, domain: str) -> None:
        """
        Check a domain against VirusTotal and report results.
        
        Args:
            update (Update): The update object
            domain (str): The domain to check
        """
        try:
            is_malicious, malicious_count, total_engines = self.vt_checker.check_domain(domain)
            
            if is_malicious:
                await update.message.reply_text(
                    f"⚠️ WARNING: Potentially malicious domain detected!\n\n"
                    f"Domain: {domain}\n"
                    f"Detections: {malicious_count}/{total_engines} security vendors flagged this domain as malicious.\n\n"
                    f"Recommendation: Do not visit websites on this domain."
                )
            else:
                await update.message.reply_text(
                    f"✅ Domain seems safe: {domain}\n"
                    f"Detections: {malicious_count}/{total_engines} security vendors flagged this domain.\n\n"
                    f"Note: Always be cautious when visiting unknown websites."
                )
        except Exception as e:
            logger.error(f"Error checking domain {domain}: {e}")
            await update.message.reply_text(
                f"Error checking domain: {domain}\n"
                f"Please try again later or report this issue to the bot administrator."
            )
    
    async def error_handler(self, update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
        """
        Handle errors.
        
        Args:
            update (object): The update object
            context (ContextTypes.DEFAULT_TYPE): The context object
        """
        logger.error(f"Update {update} caused error: {context.error}")
    
    def run(self) -> None:
        """Run the bot."""
        self.application.run_polling()


def main():
    """Main function."""
    try:
        # Initialize the VirusTotal checker
        vt_checker = VirusTotalChecker(VIRUSTOTAL_API_KEY)
        
        # Initialize and run the Telegram bot
        bot = TelegramBot(TELEGRAM_TOKEN, vt_checker)
        logger.info("Starting bot...")
        bot.run()
    except Exception as e:
        logger.error(f"Critical error: {e}")


if __name__ == "__main__":
    main()