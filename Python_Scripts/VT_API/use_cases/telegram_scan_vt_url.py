import requests
import json
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# Replace 'YOUR_BOT_TOKEN' with your actual Telegram bot token
bot_token = os.environ.get('BOT_TOKEN')
# Replace 'YOUR_VT_APIKEY' with your actual VirusTotal API key
vt_api_key = os.environ.get('VT_APIKEY')

async def start(update, context):
    await update.message.reply_text(
        "Welcome to the VirusTotal Scanner Bot!\n"
        "Use the /scan command to check the safety of a URL."
    )

async def help_command(update, context):
    await update.message.reply_text(
        "Available commands:\n"
        "/start - Start the bot\n"
        "/help - Display this help message\n"
        "/scan <target> - Check the safety of a URL"
    )

async def scan(update, context):
    try:
        url = context.args[0]
    except IndexError:
        await update.message.reply_text("Usage: /scan <target>")
        return

    # Create the request to the VirusTotal API
    #params = {'apikey': vt_api_key, 'resource': url}
    #response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params)

    context = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    context = f'https://www.virustotal.com/api/v3/urls/{url}'
    headers = {'Accept': 'application/json', 'x-apikey': os.environ['VT_APIKEY']}
    res = requests.get(context, headers=headers)

    # Analyze the API response
    json_response = json.loads(response.text)
    if json_response['response_code'] == 1:
        message = (
            f"Number of antivirus detecting the threat: {json_response['positives']}\n"
            f"Total number of antivirus used for analysis: {json_response['total']}\n"
            f"Detection rate of the threat: {json_response['positives'] / json_response['total'] * 100:.2f}%"
        )
    else:
        message = f"Error analyzing the web page: {json_response['verbose_msg']}"

    await update.message.reply_text(message)

# Build the bot application
app = ApplicationBuilder().token(bot_token).build()

# Add command handlers
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("help", help_command))
app.add_handler(CommandHandler("scan", scan))

# Run the bot
app.run_polling()
