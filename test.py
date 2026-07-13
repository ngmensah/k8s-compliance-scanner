from dotenv import load_dotenv
import os
import anthropic

# Load the .env file
load_dotenv()

# Grab the API Key
api_key = os.getenv("ANTHROPIC_API_KEY")

# Quick check to confirm the key loaded
if not api_key:
    print("API key not found. Check your .env file.")
else:
    print("API key loaded successfully.")

# initialize the client
client = anthropic.Anthropic(api_key=api_key)

# Send a test message
message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "Say hello and confirm the API is working."}
    ]
)

print(message.content[0].text)