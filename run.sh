#!/usr/bin/env bash
# Same as `cd frontend && npm run dev`: starts the UI on http://localhost:5173 and
# the backend on :8000 together. Ctrl+C stops both.
#   ./run.sh          real Gemini (needs GEMINI_API_KEY in backend/.env)
#   ./run.sh --stub   offline rule-based stub, no key (UI testing only, NOT an AI)
cd "$(dirname "$0")/frontend"
if [ "$1" = "--stub" ]; then export VOID_STUB_LLM=1; fi
[ -d node_modules ] || npm install
exec npm run dev
