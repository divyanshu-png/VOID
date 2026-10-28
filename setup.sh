#!/usr/bin/env bash
# One-time setup for VOID on macOS / Linux. Run from the repo root:  ./setup.sh
set -e
cd "$(dirname "$0")"

echo "==> Python"
PY=$(command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3)
"$PY" -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ needed"' || { echo "Install Python 3.10+ (brew install python@3.11)"; exit 1; }
"$PY" -m venv backend/.venv
backend/.venv/bin/pip install -q --upgrade pip
backend/.venv/bin/pip install -q -r backend/requirements.txt
echo "    backend dependencies installed in backend/.venv"

[ -f backend/.env ] || cp .env.example backend/.env
if grep -q '^GEMINI_API_KEY=$' backend/.env; then
  echo "    !! Put your Gemini key in backend/.env  (GEMINI_API_KEY=...)"
fi

echo "==> Web dashboard"
if command -v npm >/dev/null; then
  (cd frontend && npm install --no-audit --no-fund --silent && npm run build --silent) && echo "    built frontend/dist"
else
  echo "    npm not found; using the prebuilt frontend/dist (install Node to rebuild)"
fi

echo "==> Sandbox image"
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  docker build -q -t void-sandbox:latest ./sandbox >/dev/null && echo "    built void-sandbox:latest (tests will run in throwaway containers)"
else
  echo "    Docker not running; VOID will use the subprocess fallback. Start Docker Desktop and re-run ./setup.sh to enable containers."
fi

echo "==> VS Code extension"
if command -v code >/dev/null; then
  code --install-extension vscode-extension/void-0.2.0.vsix --force >/dev/null && echo "    installed VOID extension"
else
  echo "    'code' command not found. In VS Code: Extensions > ... > Install from VSIX > vscode-extension/void-0.2.0.vsix"
fi

echo "==> Tests"
(cd backend && SANDBOX_MODE=subprocess .venv/bin/python -m pytest -q -p no:cacheprovider | tail -1)

echo
echo "Done. Start VOID with:  ./run.sh   then open http://localhost:8000"
