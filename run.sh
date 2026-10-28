#!/usr/bin/env bash
# Start the VOID backend + dashboard on http://localhost:8000
#   ./run.sh          real Gemini (needs GEMINI_API_KEY in backend/.env)
#   ./run.sh --stub   offline rule-based stub, no key (UI testing only, NOT an AI)
cd "$(dirname "$0")/backend"
[ -x .venv/bin/python ] || { echo "Run ./setup.sh first"; exit 1; }
if [ "$1" = "--stub" ]; then export VOID_STUB_LLM=1; fi
( sleep 2; command -v open >/dev/null && open http://localhost:8000 ) &
exec .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
