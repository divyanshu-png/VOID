# VOID

**Autonomous, oracle-grounded security vulnerability repair for Python.**

VOID reviews Python code for security flaws, writes a fix, and only calls the fix
*verified* when independent checks agree:

1. **SAST oracle**: Bandit re-scans the patch. The original MEDIUM/HIGH findings must be gone and nothing new may appear.
2. **Execution oracle**: the generated pytest suite must pass inside a sandbox (a locked-down Docker container with no network and no secrets).
3. **Critic agent** (autonomous mode): an LLM reviewer rejects patches that hide the bug instead of fixing it, change behaviour, make out-of-scope edits to please the tests, or come with hollow tests.

When a patch is rejected, a **Supervisor agent** reads the evidence and decides the next step: repair the code, rewrite only the tests, re-audit, or give up. The supervisor can never accept a patch on its own; acceptance always needs every check to pass. The retry budget is 3 attempts by default.

```
precheck (AST · Bandit · PyPI) → Auditor → Repairer → sandbox (Bandit re-scan + tests) → Critic → Supervisor
                                    ↑          ↑                                                    │
                                    │          └──────── repair code / rewrite tests ──────────────┤
                                    └──────────────────── re-audit ────────────────────────────────┤
                                                                         accept / give up → result + diff
```

What's in the repo:

| Path | What it is |
|---|---|
| `backend/` | FastAPI + LangGraph agents, sandbox, tools, API, tests |
| `backend/eval/` | Evaluation harness for the paper (configurations C0 to C4, metrics, McNemar) |
| `frontend/` | Web dashboard (React + TypeScript + Vite): live pipeline, repo mode, replays |
| `vscode-extension/` | VS Code extension: squiggles on save, *Fix with VOID* quick fix, diff + apply |
| `sandbox/` | Docker image used to run generated tests |
| `dashboard/` | Old Streamlit demo (superseded by `frontend/`) |

---

## 1. Setup (macOS / Linux)

### Requirements

* **Python 3.10+** (`brew install python@3.11`)
* **Node.js 18+** (`brew install node`)
* **Docker Desktop**, running. Optional, but without it tests run in a plain subprocess, which is not isolated.
* A **Gemini API key** (AI Studio) or a **Vertex AI** key with a Google Cloud project.

### One command

```bash
./setup.sh
```

This creates `backend/.venv`, installs the Python and Node dependencies, creates `backend/.env` from `.env.example`, builds the `void-sandbox` Docker image (if Docker is running), builds the VS Code extension and runs the tests.

### Add your key

Edit `backend/.env`:

```bash
GEMINI_API_KEY=your-key
GEMINI_MODEL=gemini-3.8-flash

# Only for Vertex AI keys (billed to the Google Cloud billing account):
GOOGLE_GENAI_USE_VERTEXAI=true
GOOGLE_CLOUD_PROJECT=your-gcp-project-id
```

With an AI Studio key, leave `GOOGLE_GENAI_USE_VERTEXAI=auto` and `GOOGLE_CLOUD_PROJECT` empty. A `402 prepayment credits are depleted` error means the AI Studio project is out of credits: top up at https://ai.studio/projects or switch to Vertex AI.

### Run

```bash
cd frontend && npm run dev
```

Open **http://localhost:5173**. This starts the backend on :8000 too (unless one is already running) and Ctrl+C stops both. The header shows the active model, oracle mode and sandbox (`docker` or `subprocess`). `./run.sh` does the same; `./run.sh --stub` uses a rule-based stub instead of Gemini for clicking through the UI without a key. **The stub is not an AI**; never present its output as results.

<details>
<summary>Manual setup instead of setup.sh</summary>

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env                    # then add your key (see above)
docker build -t void-sandbox:latest ../sandbox
cd ../frontend && npm install && npm run dev
```
</details>

Read any saved run as plain text in the terminal:

```bash
cd backend
.venv/bin/python -m app.show            # latest run
.venv/bin/python -m app.show --list     # all runs
.venv/bin/python -m app.show <id> --full   # with patched code, tests and full logs
```

## 2. The web dashboard

* **Review code**: paste code or load a sample, pick the configuration (C0 to C4) and watch every stage live: findings, each repair attempt with its oracle and critic verdicts, the supervisor's decision, the feedback sent back, generated tests, and a side-by-side diff.
* **Scan a repo**: paste a GitHub URL, pick a deliberately vulnerable demo repo, or pick a random Python repo from any GitHub user. VOID shallow-clones it, runs Bandit across every file, ranks the riskiest functions/classes, and repairs the ones you select, one after another, live.
* **Replays**: every run is recorded to `backend/replays/`. Play any of them back with original timing (1× to 8×). Use this as a safety net if the internet or the API fails during a demo.

## 3. VS Code extension

**Try it without installing (development mode):** start the backend (`cd frontend && npm run dev`), open this repo folder in VS Code, and press **F5** (Run and Debug → *Run VOID extension*). A second VS Code window opens with the extension loaded. Open any Python file there.

**Install it:** `./setup.sh` builds `vscode-extension/void-0.2.0.vsix`. In VS Code: Extensions view → `…` menu → *Install from VSIX…* → pick that file. (Or `code --install-extension vscode-extension/void-0.2.0.vsix` if the `code` command is on your PATH: in VS Code, Command Palette → *Shell Command: Install 'code' command in PATH*.)

With the backend running:

* The status bar shows **VOID** with the model; click it to open the dashboard.
* Saving a Python file runs a fast Bandit + package scan (no AI) and underlines issues.
* Hover a VOID squiggle → **Fix with VOID (verified repair)**. Only the enclosing function or class is sent; the patch is merged back into the file.
* A diff opens with VERIFIED / UNVERIFIED in the title → **Apply patch**.
* Command Palette: *VOID: Fix Vulnerability at Cursor*, *VOID: Audit & Refactor Whole File*, *VOID: Scan File for Vulnerabilities*, *VOID: Open Dashboard*.
* Settings: `void.backendUrl`, `void.dashboardUrl`, `void.oracleMode` (default `auto`), `void.scanOnSave`, `void.timeoutSeconds`.

## 4. Evaluation (paper Table II)

```bash
cd backend
python -m eval.run_eval --runs 3 --workers 8                                   # seed set, all configs
python -m eval.run_eval --dataset eval/datasets/hard.jsonl --runs 3 --workers 8 # hard set
python -m eval.run_eval --stub --runs 1                                        # offline smoke test of the harness
python -m eval.build_hard --validate                                           # rebuild + check the hard set
```

Writes `eval/results/<timestamp>/runs.csv`, `summary.csv` and a paper-ready `summary.md`.

| Config | Gate |
|---|---|
| C0 `single` | one repair attempt, no feedback |
| C1 `sast` | retry until the Bandit re-scan passes |
| C2 `exec` | retry until generated tests pass |
| C3 `dual` | retry until **both** pass |
| C4 `auto` | both oracles + critic must pass; the supervisor picks each next step (VOID default) |

Metrics: **VRR** (original MEDIUM/HIGH findings removed, nothing new), **NIR** (new issue introduced), **FP** (held-out tests pass, functionality preserved), **EBR** (held-out exploit tests pass, attack blocked), **Success** (VRR and FP and EBR), **SGG** self-grading gap (pass rate on generated tests minus held-out tests), **Feasible@1** (first attempt free of syntax/runtime errors), attempts, model calls, tokens, time. McNemar's exact test compares C3 with each other configuration.

Datasets (JSONL): `{"id", "cwe", "code", "heldout_tests", "heldout_security_tests"?}`. The held-out tests are never shown to the agent.

* `eval/datasets/seed.jsonl`: 12 single-weakness Bandit-flagged programs with behaviour-only held-out tests (`python eval/build_seed.py`).
* `eval/datasets/hard.jsonl`: 12 programs with several weaknesses, weaknesses Bandit cannot see (path traversal, SSRF, missing ownership checks, SSTI, XSS) and behaviour traps, each with held-out functional tests, exploit tests and a reference fix (`python -m eval.build_hard --validate` proves every exploit test fails on the original and passes on the reference fix).

## 5. API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | model, oracle mode, sandbox backend, key status |
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
cd backend && .venv/bin/python -m pytest -q     # 30 tests, offline, no API key needed
```

They cover the tools, the sandbox (failure classification, secret scrubbing, timeouts, module stubbing), all five modes (including C2 being fooled by trivial self-written tests, the critic vetoing a patch both oracles accept, tests-only rewrites, re-audit and give-up), streaming and the API.

## 7. Security notes

* Generated code is untrusted. With Docker, tests run in one long-lived container (`void-sandbox-pool`: `--network none`, read-only filesystem, non-root, `--cap-drop ALL`, no-new-privileges, CPU/memory/PID limits, no environment variables passed in). Each run gets its own scratch directory, deleted afterwards. The subprocess fallback hides secrets and limits resources but is not a security boundary.
* For a multi-user deployment, give each run its own microVM (e.g. Firecracker) or gVisor sandbox instead of a shared container.
* The package check flags imports that are missing from PyPI (hallucinated), very new, single-release without a source link, or near-misses of popular names (typo/combosquatting).
