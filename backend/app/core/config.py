import os
from pathlib import Path
from dotenv import load_dotenv

# Points to backend/.env
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))

if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable is missing. Check backend/.env")