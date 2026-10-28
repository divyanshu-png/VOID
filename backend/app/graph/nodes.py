"""Graph nodes. Each takes the state (and LangGraph's RunnableConfig) and returns an update."""
from __future__ import annotations

import difflib
from typing import Any, Dict, List

from app.core import config as settings
from app.core.llm import get_llm
from app.core.sandbox import execute_in_sandbox
from app.graph.state import AgentCodeState
from app.tools.ast_parser import parse_code_structure
from app.tools.pypi_validator import check_imports
from app.tools.sast_scanner import compare, run_bandit_scan

MODES = ("single", "sast", "exec", "dual")


def _llm(cfg) -> Any:
    llm = ((cfg or {}).get("configurable") or {}).get("llm")
    return llm if llm is not None else get_llm()


def _usage(llm) -> Dict[str, Any]:
    return llm.usage() if hasattr(llm, "usage") else {}


# --------------------------------------------------------------------------- #
def precheck_node(state: AgentCodeState, config=None) -> Dict[str, Any]:
    """Deterministic pre-analysis: AST, Bandit, package registry. No LLM."""
    code = state["original_code"]
    ast_info = parse_code_structure(code)
    sast = run_bandit_scan(code) if ast_info["valid_syntax"] else []
    packages = check_imports(ast_info.get("imports", []), set(state.get("local_modules") or [])) if ast_info["valid_syntax"] else []
    alerts = [
        {"package": p["package"], "import": p["import"], "status": p["status"], "warning": "; ".join(p["reasons"])}
        for p in packages if p["status"] in ("not_found", "suspicious")
    ]
    update: Dict[str, Any] = {
        "ast_metadata": ast_info,
        "sast_before": sast,
        "package_report": packages,
        "static_issues": sast + alerts,
    }
    if not ast_info["valid_syntax"]:
        update["verdict"] = "invalid_input"
        update["error_logs"] = ast_info["syntax_error"]
    return update


def audit_node(state: AgentCodeState, config=None) -> Dict[str, Any]:
    llm = _llm(config)
    result = llm.audit(state["original_code"], state.get("ast_metadata", {}),
                       state.get("sast_before", []), state.get("package_report", []))
    audit = result.model_dump() if hasattr(result, "model_dump") else dict(result)
    text = audit.get("summary", "") + "\n" + "\n".join(
        f"- [{f.get('severity')}] {f.get('title')} ({f.get('cwe')}): {f.get('explanation')} Fix: {f.get('fix')}"
        for f in audit.get("findings", [])
    )
    update = {"audit": audit, "security_audit": [{"issue": text.strip()}], "usage": _usage(llm)}
    if not audit.get("findings") and not [f for f in state.get("sast_before", []) if f.get("severity") in ("MEDIUM", "HIGH")]:
        update["verdict"] = "clean"
    return update


def _feedback(mode: str, exec_res: Dict[str, Any], sast_res: Dict[str, Any]) -> str:
    parts: List[str] = []
    if mode in ("exec", "dual") and not exec_res.get("passed"):
        status = exec_res.get("status")
        if status == "no_tests":
            parts.append("Execution oracle: no runnable tests were produced. Return a real pytest module.")
        else:
            parts.append(f"Execution oracle FAILED ({exec_res.get('error_kind') or status}). pytest output:\n"
                         + (exec_res.get("logs") or "")[-3500:])
    if mode in ("sast", "dual") and not sast_res.get("passed"):
        items = sast_res.get("remaining", []) + sast_res.get("introduced", [])
        lines = [f"- {f.get('test_id')} [{f.get('severity')}] line {f.get('line_number')}: {f.get('issue_text')}" for f in items]
        parts.append("SAST oracle FAILED. Bandit still reports:\n" + "\n".join(lines))
    return "\n\n".join(parts)


def refactor_node(state: AgentCodeState, config=None) -> Dict[str, Any]:
    llm = _llm(config)
    attempts = state.get("attempts", [])
    feedback = attempts[-1]["feedback"] if attempts else None
    findings = state.get("audit", {}).get("findings") or state.get("sast_before", [])
    result = llm.repair(state["original_code"], findings, feedback)
    return {
        "refactored_code": result.patched_code,
        "generated_tests": result.tests,
        "repair_notes": getattr(result, "notes", ""),
        "retry_count": state.get("retry_count", 0) + 1,
        "usage": _usage(llm),
    }


def sandbox_verification_node(state: AgentCodeState, config=None) -> Dict[str, Any]:
    """Run BOTH oracles on the candidate; the mode decides which ones gate acceptance."""
    mode = state.get("oracle_mode", "dual")
    patched = state.get("refactored_code") or ""
    exec_res = execute_in_sandbox(patched, state.get("generated_tests") or "").to_dict()
    sast_after = run_bandit_scan(patched)
    sast_res = compare(state.get("sast_before", []), sast_after)
    sast_res["after"] = sast_after

    gates = {"single": [], "sast": [sast_res["passed"]], "exec": [exec_res["passed"]],
             "dual": [sast_res["passed"], exec_res["passed"]]}[mode]
    accepted = all(gates) if gates else True
    feedback = "" if accepted else _feedback(mode, exec_res, sast_res)
    record = {
        "n": state.get("retry_count", 1),
        "patched_code": patched,
        "tests": state.get("generated_tests") or "",
        "exec": exec_res,
        "sast": sast_res,
        "accepted": accepted,
        "feedback": feedback,
    }
    return {
        "attempts": state.get("attempts", []) + [record],
        "exec_oracle": exec_res,
        "sast_oracle": sast_res,
        "test_execution_status": "PASSED" if exec_res["passed"] else "FAILED",
        "error_logs": None if exec_res["passed"] else exec_res.get("logs"),
    }


def presentation_node(state: AgentCodeState, config=None) -> Dict[str, Any]:
    verdict = state.get("verdict")
    attempts = state.get("attempts", [])
    if not verdict:
        mode = state.get("oracle_mode", "dual")
        last = attempts[-1] if attempts else {}
        both = last.get("exec", {}).get("passed") and last.get("sast", {}).get("passed")
        if mode == "single":
            verdict = "verified" if both else "unverified"
        else:
            verdict = "verified" if last.get("accepted") and both else "unverified"
    orig = state["original_code"].splitlines(keepends=True)
    new = (state.get("refactored_code") or state["original_code"]).splitlines(keepends=True)
    diff = "".join(difflib.unified_diff(orig, new, fromfile="original.py", tofile="patched.py"))
    return {"verdict": verdict, "final_diff": diff}


# --------------------------------------------------------------------------- routing
def route_after_precheck(state: AgentCodeState) -> str:
    return "presentation" if state.get("verdict") == "invalid_input" else "security_audit"


def route_after_audit(state: AgentCodeState) -> str:
    return "presentation" if state.get("verdict") == "clean" else "refactor"


def route_after_sandbox(state: AgentCodeState) -> str:
    last = (state.get("attempts") or [{}])[-1]
    mode = state.get("oracle_mode", "dual")
    limit = state.get("max_retries") or settings.MAX_RETRIES
    if mode == "single" or last.get("accepted") or state.get("retry_count", 0) >= limit:
        return "presentation"
    return "refactor"
