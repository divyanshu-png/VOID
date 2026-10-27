import os
from pathlib import Path
from dotenv import load_dotenv

# Try backend/.env first, then root .env
backend_dir = Path(__file__).resolve().parent.parent.parent
root_dir = backend_dir.parent

if (backend_dir / ".env").exists():
    load_dotenv(backend_dir / ".env")
elif (root_dir / ".env").exists():
    load_dotenv(root_dir / ".env")
else:
    load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))

if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable is missing. Check your .env file.")