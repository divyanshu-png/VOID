"""Turns graph execution into compact, JSON-friendly events for the API and UI."""
from __future__ import annotations

from typing import Any, Dict, Iterator, Optional

from app.graph.workflow import stream_review
from app.tools.ast_parser import extract_enclosing, merge_patch_into_file

LOG_LIMIT = 4000


def _trim(text: Optional[str], n: int = LOG_LIMIT) -> Optional[str]:
    if text and len(text) > n:
        return "…" + text[-n:]
    return text


def summarise(node: str, update: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    if node == "ast_parser":
        return {k: update.get(k) for k in ("ast_metadata", "sast_before", "package_report", "verdict", "error_logs")}
    if node == "security_audit":
        return {"audit": update.get("audit"), "verdict": update.get("verdict")}
    if node == "refactor":
        return {"attempt": update.get("retry_count"), "patched_code": update.get("refactored_code"),
                "tests": update.get("generated_tests"), "notes": update.get("repair_notes")}
    if node == "sandbox":
        last = dict((update.get("attempts") or [{}])[-1])
        ex = dict(last.get("exec", {}))
        ex["logs"] = _trim(ex.get("logs"))
        sa = {k: v for k, v in (last.get("sast") or {}).items() if k != "after"}
        return {"attempt": last.get("n"), "accepted": last.get("accepted"), "exec": ex, "sast": sa,
                "feedback": _trim(last.get("feedback"), 2500)}
    if node == "presentation":
        return {"verdict": update.get("verdict"), "final_diff": update.get("final_diff")}
    return {}


def final_result(state: Dict[str, Any]) -> Dict[str, Any]:
    attempts = []
    for a in state.get("attempts", []):
        ex = dict(a.get("exec", {}))
        ex["logs"] = _trim(ex.get("logs"))
        attempts.append({"n": a.get("n"), "accepted": a.get("accepted"), "exec": ex,
                         "sast": {k: v for k, v in (a.get("sast") or {}).items() if k != "after"}})
    verdict = state.get("verdict", "")
    return {
        "status": "SUCCESS",
        "verdict": verdict,
        "oracle_mode": state.get("oracle_mode"),
        "audit": state.get("audit") or {},
        "audit_notes": state.get("security_audit", []),
        "sast_before": state.get("sast_before", []),
        "package_report": state.get("package_report", []),
        "refactored_code": state.get("refactored_code"),
        "generated_tests": state.get("generated_tests"),
        "diff": state.get("final_diff"),
        "test_status": state.get("test_execution_status", "UNKNOWN"),
        "sast_status": "PASSED" if (state.get("sast_oracle") or {}).get("passed") else
                       ("FAILED" if state.get("sast_oracle") else "N/A"),
        "retries": state.get("retry_count", 0),
        "attempts": attempts,
        "error_logs": _trim(state.get("error_logs")),
        "usage": state.get("usage", {}),
    }


def run_events(code: str, language: str = "python", oracle_mode: Optional[str] = None,
               max_retries: Optional[int] = None, focus_line: Optional[int] = None,
               local_modules=None, llm=None) -> Iterator[Dict[str, Any]]:
    """Yield {'event': ..., 'data': ...} dicts for one review."""
    focus = None
    target = code
    if focus_line:
        focus = extract_enclosing(code, focus_line)
        if focus:
            target = focus["snippet"]
            yield {"event": "focus", "data": {k: focus[k] for k in ("name", "kind", "start_line", "end_line", "snippet")}}
    state: Dict[str, Any] = {}
    for node, update, state in stream_review(target, language, oracle_mode, max_retries, llm=llm,
                                             local_modules=local_modules):
        yield {"event": "node", "data": {"node": node, **summarise(node, update, state)}}
    result = final_result(state)
    if focus:
        result["focus"] = {k: focus[k] for k in ("name", "kind", "start_line", "end_line")}
        result["merged_file"] = (merge_patch_into_file(code, focus, state["refactored_code"])
                                 if state.get("refactored_code") else code)
    yield {"event": "done", "data": result}
