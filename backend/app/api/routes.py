from __future__ import annotations

import json
import traceback
from typing import Any, Dict, Iterator

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from app.core import config
from app.core.llm import LLMError
from app.api.schemas import AuditRequest, AuditResponse, RepoRunRequest, RepoScanRequest, ScanRequest
from app.services.replays import Recorder, list_replays, load_replay
from app.services.runner import run_events
from app.tools.ast_parser import parse_code_structure
from app.tools.pypi_validator import check_imports
from app.tools.repo_scanner import DEMO_REPOS, random_repo, scan_repo
from app.tools.sast_scanner import run_bandit_scan

router = APIRouter()


def _sse(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


def _require_code(code: str) -> None:
    if not code.strip():
        raise HTTPException(status_code=400, detail="Source code payload cannot be empty.")


# ----------------------------------------------------------------- single review
def _run_blocking(payload: AuditRequest) -> Dict[str, Any]:
    rec = Recorder("snippet", f"Snippet review ({payload.oracle_mode or 'default'})", {"code": payload.code})
    result: Dict[str, Any] = {}
    for ev in run_events(payload.code, payload.language or "python", payload.oracle_mode,
                         payload.max_retries, payload.focus_line):
        rec.add(ev["event"], ev["data"])
        if ev["event"] == "done":
            result = ev["data"]
    result["replay_id"] = rec.save()
    return result


@router.post("/audit", response_model=AuditResponse)
async def review_code(payload: AuditRequest):
    _require_code(payload.code)
    try:
        return await run_in_threadpool(_run_blocking, payload)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Agent runtime failure: {e}")


@router.post("/audit/stream")
def review_code_stream(payload: AuditRequest):
    """Server-Sent Events: one `node` event per pipeline step, then `done`."""
    _require_code(payload.code)

    def gen() -> Iterator[str]:
        rec = Recorder("snippet", f"Snippet review ({payload.oracle_mode or 'default'})", {"code": payload.code})
        yield _sse("start", {"replay_id": rec.id})
        try:
            for ev in run_events(payload.code, payload.language or "python", payload.oracle_mode,
                                 payload.max_retries, payload.focus_line):
                rec.add(ev["event"], ev["data"])
                if ev["event"] == "done":
                    ev["data"]["replay_id"] = rec.id
                yield _sse(ev["event"], ev["data"])
        except Exception as e:
            if not isinstance(e, LLMError):
                traceback.print_exc()
            rec.add("error", {"message": str(e)})
            yield _sse("error", {"message": str(e)})
        finally:
            rec.save()

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ----------------------------------------------------------------- fast scan (no LLM)
@router.post("/scan")
async def quick_scan(payload: ScanRequest):
    """Bandit + package checks only. Used by the VS Code extension on save."""
    def work():
        ast_info = parse_code_structure(payload.code)
        if not ast_info["valid_syntax"]:
            return {"valid_syntax": False, "syntax_error": ast_info["syntax_error"], "findings": [], "packages": []}
        return {"valid_syntax": True, "findings": run_bandit_scan(payload.code),
                "packages": check_imports(ast_info["imports"])}
    return await run_in_threadpool(work)


# ----------------------------------------------------------------- samples
@router.get("/samples")
def samples():
    """Built-in vulnerable examples (the evaluation seed set) for the UI's sample picker."""
    path = config.BACKEND_DIR / "eval" / "datasets" / "seed.jsonl"
    items = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                d = json.loads(line)
                items.append({"id": d["id"], "cwe": d.get("cwe", ""), "code": d["code"]})
    return {"samples": items}


# ----------------------------------------------------------------- repo mode
@router.get("/repo/demos")
def repo_demos():
    return {"repos": DEMO_REPOS}


@router.get("/repo/random")
async def repo_random(user: str = ""):
    try:
        return {"url": await run_in_threadpool(random_repo, user or None)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/repo/scan")
async def repo_scan(payload: RepoScanRequest):
    try:
        return await run_in_threadpool(scan_repo, payload.url, payload.min_severity, payload.limit, payload.refresh)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/repo/run")
def repo_run(payload: RepoRunRequest):
    """SSE: scan the repo, then run VOID on each selected block in turn."""

    def gen() -> Iterator[str]:
        rec = Recorder("repo", f"Repo run: {payload.url.split('github.com/')[-1]}", {"url": payload.url})
        yield _sse("start", {"replay_id": rec.id})
        summary = {"verified": 0, "unverified": 0, "clean": 0, "invalid_input": 0, "errors": 0}
        try:
            scan = scan_repo(payload.url, payload.min_severity, 100)
            targets = scan["targets"]
            if payload.target_ids:
                targets = [t for t in targets if t["id"] in payload.target_ids]
            targets = targets[: payload.max_targets]
            scan_view = {k: v for k, v in scan.items() if k != "local_modules"}
            scan_view["selected"] = [t["id"] for t in targets]
            yield _sse("scan", rec.add("scan", scan_view)["data"])
            for t in targets:
                yield _sse("target_start", rec.add("target_start", {"id": t["id"], "file": t["file"], "name": t["name"]})["data"])
                try:
                    for ev in run_events(t["snippet"], "python", payload.oracle_mode, local_modules=scan["local_modules"]):
                        data = {"target": t["id"], **ev["data"]}
                        rec.add(ev["event"], data)
                        if ev["event"] == "done":
                            summary[ev["data"]["verdict"]] = summary.get(ev["data"]["verdict"], 0) + 1
                            yield _sse("target_done", data)
                        else:
                            yield _sse(ev["event"], data)
                except LLMError as e:
                    # Key / billing / model problems affect every target: stop and say why.
                    summary["errors"] += 1
                    yield _sse("target_error", rec.add("target_error", {"target": t["id"], "message": str(e)})["data"])
                    yield _sse("error", rec.add("error", {"message": str(e)})["data"])
                    return
                except Exception as e:
                    traceback.print_exc()
                    summary["errors"] += 1
                    yield _sse("target_error", rec.add("target_error", {"target": t["id"], "message": str(e)})["data"])
            yield _sse("summary", rec.add("summary", summary)["data"])
        except Exception as e:
            traceback.print_exc()
            yield _sse("error", rec.add("error", {"message": str(e)})["data"])
        finally:
            rec.save()

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ----------------------------------------------------------------- replays
@router.get("/replays")
def replays():
    return {"replays": list_replays()}


@router.get("/replays/{replay_id}")
def replay(replay_id: str):
    doc = load_replay(replay_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Replay not found")
    return doc
