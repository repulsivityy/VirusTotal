# Telegram Anti-Phishing Bot

A simple yet powerful Telegram bot that scans URLs and domains found in messages. It uses the VirusTotal and Google Web Risk APIs to check for potential phishing, malware, or other threats in real-time.

![Bot Demo](https://i.imgur.com/your-demo-image.gif) ## Features

-   **Dual API Checks:** Leverages both VirusTotal (70+ scanners) and Google Web Risk for comprehensive threat analysis.
-   **Checks URLs and Domains:** Scans both full URLs (`https://example.com/bad-path`) and standalone domains (`example.com`).
-   **Concurrent Scans:** Processes multiple links found in a single message at the same time for a fast user experience.
-   **Efficient Networking:** Uses an intelligent session manager that closes network connections during idle periods to save resources.
-   **Clear Results:** Provides a simple, emoji-coded risk level (`DANGER`, `WARNING`, `SAFE`) and a clear recommendation.

## Setup and Installation

Follow these steps to get your own instance of the bot running.

### 1. Prerequisites

-   Python 3.9 or higher
-   A Telegram Bot Token from [BotFather](https://t.me/botfather)
-   A VirusTotal API Key from [VirusTotal](https://developers.virustotal.com/reference)
-   A Google Web Risk API Key from the [Google Cloud Console](https://cloud.google.com/web-risk/docs/setting-up)

### 2. Installation

First, clone the repository to your local machine or server:
```bash
git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
cd your-repo-name
```

Next, create a `requirements.txt` file with the following content:

```txt
# requirements.txt
python-telegram-bot
aiohttp
```

Now, install the required Python libraries:
```bash
pip install -r requirements.txt
```

### 3. Configuration

The bot is configured using environment variables. This is a secure way to handle your secret API keys and tokens without hardcoding them.

**On Linux or macOS:**
```bash
export TELEGRAM_TOKEN="YOUR_TELEGRAM_TOKEN"
export VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
export WEBRISK_API_KEY="YOUR_WEBRISK_API_KEY"
```

**On Windows (Command Prompt):**
```bash
set TELEGRAM_TOKEN="YOUR_TELEGRAM_TOKEN"
set VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
set WEBRISK_API_KEY="YOUR_WEBRISK_API_KEY"
```

Replace the `"YOUR_..."` values with your actual keys and token. You must set these variables in the same terminal session where you will run the bot.

## Running the Bot

Once the dependencies are installed and the environment variables are set, you can run the bot with a single command.

Assuming your Python script is named `phishing_bot.py`:
```bash
python phishing_bot.py
```

You should see a log message indicating the bot has started successfully:
```
INFO:__main__:Starting fully optimized bot...
```

## How to Use

Simply start a chat with your bot on Telegram and send it any message that contains one or more URLs or domains.

-   **Example Message:** `hey can you check www.example.com and this link http://suspicious-site.net/login.php`
-   The bot will reply with an "Analyzing..." message for each item and then update it with the final security report.

You can also use the following commands:
-   `/start`: Displays a welcome message.
-   `/help`: Explains what the bot does.