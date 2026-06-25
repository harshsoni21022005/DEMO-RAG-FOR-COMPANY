import os
from dotenv import load_dotenv
load_dotenv()
key = os.getenv("GROQ_API_KEY")
print(f"Loaded Key: {key[:10]}...{key[-10:] if key else ''}")
