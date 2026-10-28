"""Central configuration. Values come from environment variables or a .env file.

Nothing here raises at import time, so tests, replays and the repo scanner work
without an API key. The key is only checked when an LLM call is actually made.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
ROOT_DIR = BACKEND_DIR.parent

for candidate in (BACKEND_DIR / ".env", ROOT_DIR / ".env"):
    if candidate.exists():
        load_dotenv(candidate)
        break
else:
    load_dotenv()


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


# --- LLM ---------------------------------------------------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))

# --- Server ------------------------------------------------------------------
HOST = os.getenv("HOST", "0.0.0.0")
PORT = _int("PORT", 8000)

# --- Agent loop --------------------------------------------------------------
MAX_RETRIES = _int("MAX_RETRIES", 3)
# Which oracles gate acceptance of a patch:
#   single = C0 (one repair attempt, no feedback loop)
#   sast   = C1 (Bandit re-scan only)
#   exec   = C2 (generated tests only)
#   dual   = C3 (both must pass)  <- VOID default
ORACLE_MODE = os.getenv("ORACLE_MODE", "dual")

# --- Sandbox -----------------------------------------------------------------
# auto  = use Docker if it is available, otherwise the hardened subprocess
# docker / subprocess = force one of them
SANDBOX_MODE = os.getenv("SANDBOX_MODE", "auto")
SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "void-sandbox:latest")
SANDBOX_TIMEOUT = _int("SANDBOX_TIMEOUT", 10)
SANDBOX_MEMORY_MB = _int("SANDBOX_MEMORY_MB", 256)

# --- Storage -----------------------------------------------------------------
REPLAY_DIR = Path(os.getenv("REPLAY_DIR", str(BACKEND_DIR / "replays")))
REPO_CACHE_DIR = Path(os.getenv("REPO_CACHE_DIR", str(BACKEND_DIR / ".repo_cache")))

# --- Package checks ----------------------------------------------------------
PYPI_TIMEOUT = float(os.getenv("PYPI_TIMEOUT", "3.0"))
NEW_PACKAGE_DAYS = _int("NEW_PACKAGE_DAYS", 90)

# --- GitHub (repo mode) ------------------------------------------------------
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # optional, raises API rate limits

# --- Development -------------------------------------------------------------
# Use the rule-based stub instead of Gemini (offline UI testing; NOT an AI).
STUB_LLM = os.getenv("VOID_STUB_LLM", "0") == "1"


def require_api_key() -> str:
    if not GEMINI_API_KEY:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Add it to backend/.env (see .env.example)."
        )
    return GEMINI_API_KEY
