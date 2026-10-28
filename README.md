# VOID

**Oracle-grounded self-correction for LLM-based security vulnerability repair.**

VOID reviews Python code for security flaws, writes a fix, and only calls the fix
*verified* when two independent checks (oracles) agree:

1. **SAST oracle**: Bandit re-scans the patch. The original MEDIUM/HIGH findings must be gone and nothing new may appear.
2. **Execution oracle**: the generated pytest suite must pass inside a sandbox (a throwaway Docker container with no network and no secrets).

If either rejects the patch, the reason is fed back to the repair agent and it tries again (3 attempts by default).

```
precheck (AST · Bandit · PyPI) → audit (LLM) → repair (LLM) → verify (Bandit re-scan + sandboxed tests)
                                                   ↑                          │ rejected & retries left
                                                   └──────────────────────────┘
                                                                              │ accepted / budget spent
                                                                              ↓
                                                                   result: VERIFIED / UNVERIFIED + diff
```

What's in the repo:

| Path | What it is |
|---|---|
| `backend/` | FastAPI + LangGraph agent, sandbox, tools, API, tests |
| `backend/eval/` | Evaluation harness for the paper (configurations C0 to C3, metrics, McNemar) |
| `frontend/` | Web dashboard: live pipeline, repo mode, replays |
| `vscode-extension/` | VS Code extension: squiggles on save, *Fix with VOID* quick fix, diff + apply |
| `sandbox/` | Docker image used to run generated tests |
| `dashboard/` | Old Streamlit demo (superseded by `frontend/`) |

---

## 1. Quick start (macOS / Linux)

Easiest: `./setup.sh` once (put your key in `backend/.env`), then `cd frontend && npm run dev` (or `./run.sh`) and open http://localhost:5173; it starts the backend on :8000 too. The manual steps are below.

```bash
# backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env          # then put your GEMINI_API_KEY in .env

# sandbox image (needs Docker Desktop running). Optional but recommended.
docker build -t void-sandbox:latest ../sandbox

# web UI (build once; the backend serves it)
cd ../frontend && npm install && npm run build && cd ../backend

# run
uvicorn app.main:app --port 8000
```

Open **http://localhost:8000**. The header shows which model and which sandbox are active.

* No Docker? VOID falls back to a hardened subprocess (scrubbed environment, CPU/memory limits, timeout). The header shows `sandbox: subprocess`.
* No API key yet? Start with `VOID_STUB_LLM=1 uvicorn app.main:app` to click through the UI with a rule-based stub. **The stub is not an AI**; never present its output as results.

`npm run dev` also starts the backend unless one is already running on :8000.

## 2. The web dashboard

* **Review code**: paste code or load a sample, pick the oracle configuration (C0 to C3) and watch every stage live: findings, each repair attempt with its two oracle verdicts, the feedback sent back, generated tests, and a side-by-side diff.
* **Scan a repo**: paste a GitHub URL, pick a deliberately vulnerable demo repo, or pick a random Python repo from any GitHub user. VOID shallow-clones it, runs Bandit across every file, ranks the riskiest functions/classes, and repairs the ones you select, one after another, live.
* **Replays**: every run is recorded to `backend/replays/`. Play any of them back with original timing (1× to 8×). Use this as a safety net if the internet or the API fails during a demo.

## 3. VS Code extension

```bash
cd vscode-extension && npm install && npm run package && npx vsce package --skip-license
code --install-extension void-0.2.0.vsix
```

With the backend running:

* Saving a Python file runs a fast Bandit + package scan (no AI) and underlines issues.
* Hover a VOID squiggle → **Fix with VOID (verified repair)**. Only the enclosing function or class is sent; the patch is merged back into the file.
* A diff opens with VERIFIED / UNVERIFIED in the title → **Apply patch**.
* Settings: `void.backendUrl`, `void.oracleMode`, `void.scanOnSave`, `void.timeoutSeconds`.

## 4. Evaluation (paper Table II)

```bash
cd backend
python -m eval.run_eval --runs 3                       # all four configs on the seed set
python -m eval.run_eval --dataset my.jsonl --semgrep   # your own dataset + Semgrep cross-check
python -m eval.run_eval --stub --runs 1                # offline smoke test of the harness
```

Writes `eval/results/<timestamp>/runs.csv`, `summary.csv` and a paper-ready `summary.md`.

| Config | Gate |
|---|---|
| C0 `single` | one repair attempt, no feedback |
| C1 `sast` | retry until the Bandit re-scan passes |
| C2 `exec` | retry until generated tests pass |
| C3 `dual` | retry until **both** pass (VOID) |

Metrics: **VRR** (original MEDIUM/HIGH findings removed, nothing new), **NIR** (new issue introduced), **FP** (held-out tests pass, functionality preserved), **Success** (VRR and FP), **SGG** self-grading gap (pass rate on generated tests minus held-out tests), **Feasible@1** (first attempt free of syntax/runtime errors), attempts, model calls, tokens, time. McNemar's exact test compares C3 with each baseline.

Dataset format (JSONL): `{"id": ..., "code": <vulnerable program>, "heldout_tests": <pytest code, never shown to the agent>, "cwe": ...}`.
`eval/datasets/seed.jsonl` has 12 Bandit-flagged programs with behaviour-only held-out tests (rebuild with `python eval/build_seed.py`).

## 5. API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | model, sandbox backend, key status |
| POST | `/api/v1/audit` | full review, JSON result (`code`, `oracle_mode`, `max_retries`, `focus_line`) |
| POST | `/api/v1/audit/stream` | same, as Server-Sent Events (one event per stage) |
| POST | `/api/v1/scan` | Bandit + package checks only (fast, no LLM) |
| GET | `/api/v1/samples` | built-in vulnerable samples |
| GET | `/api/v1/repo/demos`, `/api/v1/repo/random?user=` | demo repos / random repo of a user |
| POST | `/api/v1/repo/scan` | clone + rank risky blocks |
| POST | `/api/v1/repo/run` | SSE: repair selected blocks one by one |
| GET | `/api/v1/replays`, `/api/v1/replays/{id}` | recorded runs |

## 6. Tests

```bash
cd backend && pytest -q        # 23 tests, offline, no API key needed
```

They cover the tools, the sandbox (failure classification, secret scrubbing, timeouts), all four oracle modes (including C2 being fooled by trivial self-written tests, which C3 catches), streaming and the API.

## 7. Security notes

* Generated code is untrusted. Use the Docker sandbox (`--network none`, read-only, non-root, `--cap-drop ALL`, CPU/memory/PID limits, no environment variables passed in). The subprocess fallback hides secrets and limits resources but is not a security boundary.
* For a multi-user deployment, run each sandbox in a microVM (e.g. Firecracker) or gVisor instead of a plain container.
* The package check flags imports that are missing from PyPI (hallucinated), very new, single-release without a source link, or near-misses of popular names (typo/combosquatting).
