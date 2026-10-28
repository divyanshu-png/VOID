"""Print a saved run (replay) as plain text, for reading in a terminal.

    cd backend
    python -m app.show              # latest replay
    python -m app.show --list       # all replays
    python -m app.show <replay-id> --full   # include patched code, tests and full sandbox logs
"""
from __future__ import annotations

import argparse
import sys
import textwrap
from typing import Any, Dict, List

from app.services.replays import list_replays, load_replay

RULE = "-" * 78


def _tail(text: str, n: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else "..." + text[-n:]


def _indent(text: str, pad: str = "    ") -> str:
    return textwrap.indent((text or "").rstrip(), pad)


def _scan(d: Dict[str, Any]) -> List[str]:
    out = [f"Repo: {d.get('repo')}  ({d.get('python_files')} Python files, "
           f"{d.get('total_findings')} Bandit findings {d.get('by_severity')})"]
    for t in d.get("targets", []):
        out.append(f"  target {t['id']}: {t['file']} · {t['name']} (lines {t.get('start_line')}-{t.get('end_line')})")
    return out


def _node(d: Dict[str, Any], full: bool) -> List[str]:
    node, out = d.get("node"), []
    if node == "ast_parser":
        out.append("[pre-checks]")
        for f in d.get("sast_before") or []:
            out.append(f"  bandit {f.get('test_id')} [{f.get('severity')}] L{f.get('line_number')}: {f.get('issue_text')}")
        bad = [p for p in d.get("package_report") or [] if p.get("status") != "ok"]
        pkgs = len(d.get("package_report") or [])
        out.append(f"  packages: {pkgs} checked, " + (", ".join(f"{p['package']}={p['status']}" for p in bad) or "all ok"))
        if d.get("error_logs"):
            out.append(f"  error: {d['error_logs']}")
    elif node == "security_audit":
        audit = d.get("audit") or {}
        out.append("[audit] " + audit.get("summary", ""))
        for f in audit.get("findings", []):
            out.append(f"  {f.get('severity')} {f.get('cwe')} L{f.get('line')}: {f.get('title')}")
            out.append(_indent(f"why: {f.get('explanation')}\nfix: {f.get('fix')}", "      "))
    elif node == "refactor":
        out.append(f"[repair attempt {d.get('attempt')}] {d.get('notes') or ''}")
        if full:
            out += ["  patched code:", _indent(d.get("patched_code")), "  generated tests:", _indent(d.get("tests"))]
    elif node == "sandbox":
        ex, sa = d.get("exec") or {}, d.get("sast") or {}
        out.append(f"[verify attempt {d.get('attempt')}] {'ACCEPTED' if d.get('accepted') else 'REJECTED'}")
        out.append(f"  SAST: {'pass' if sa.get('passed') else 'FAIL'} (resolved {sa.get('resolved')}, "
                   f"remaining {len(sa.get('remaining') or [])}, introduced {len(sa.get('introduced') or [])})")
        out.append(f"  EXEC: {ex.get('status')} {ex.get('error_kind') or ''} · {ex.get('tests_collected')} tests "
                   f"· backend={ex.get('backend')} · {ex.get('duration_s')}s")
        if not ex.get("passed"):
            out.append(_indent(_tail(ex.get("logs", ""), 100_000 if full else 1200), "    | "))
    elif node == "critic":
        c = d.get("critic") or {}
        out.append(f"[critic attempt {d.get('attempt')}] {'APPROVED' if c.get('approved') else 'REJECTED'} {c.get('summary') or ''}")
        out += [f"  - {i}" for i in c.get("issues") or []]
    elif node == "supervisor":
        dec = d.get("decision") or {}
        out.append(f"[supervisor] -> {dec.get('action')}: {dec.get('reason')}")
        if dec.get("guidance"):
            out.append(_indent(f"guidance: {dec['guidance']}", "  "))
    elif node == "presentation":
        out.append(f"[result] {str(d.get('verdict')).upper()}")
    return out


def _done(d: Dict[str, Any], full: bool) -> List[str]:
    u = d.get("usage") or {}
    out = [f"VERDICT: {str(d.get('verdict')).upper()} · attempts {d.get('retries')} · {u.get('llm_calls')} model calls "
           f"· {u.get('model')} · mode {d.get('oracle_mode')}"]
    if d.get("diff"):
        out += ["diff:", _indent(d["diff"] if full else _tail(d["diff"], 4000))]
    return out


def render(doc: Dict[str, Any], full: bool = False) -> str:
    lines = [RULE, f"{doc.get('title')}  ·  {doc.get('created')}  ·  {doc.get('duration_s')}s  ·  id {doc.get('id')}", RULE]
    for e in doc.get("events", []):
        ev, d = e.get("event"), e.get("data") or {}
        if ev == "scan":
            lines += _scan(d)
        elif ev == "target_start":
            lines += ["", RULE, f"TARGET {d.get('file')} · {d.get('name')}", RULE]
        elif ev == "node":
            lines += _node(d, full)
        elif ev == "done":
            lines += [""] + _done(d, full)
        elif ev == "target_error":
            lines.append(f"ERROR: {d.get('error') or d}")
        elif ev == "summary":
            lines += ["", "SUMMARY: " + ", ".join(f"{k}={v}" for k, v in d.items())]
        elif ev == "focus":
            lines.append(f"focus: {d.get('kind')} {d.get('name')} (lines {d.get('start_line')}-{d.get('end_line')})")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("replay", nargs="?", default="latest")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--full", action="store_true", help="include patched code, tests and full logs")
    args = ap.parse_args(argv)

    items = list_replays()
    if args.list:
        for r in items:
            print(f"{r['id']}  {r['kind']:<7} {r['title']}")
        return 0
    if not items:
        print("No replays saved yet.", file=sys.stderr)
        return 1
    doc = load_replay(items[0]["id"] if args.replay == "latest" else args.replay)
    if not doc:
        print(f"Replay {args.replay} not found (see --list).", file=sys.stderr)
        return 1
    print(render(doc, args.full))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
