"""SAST oracle built on Bandit."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _bandit_cmd() -> List[str]:
    exe = shutil.which("bandit")
    return [exe] if exe else [sys.executable, "-m", "bandit"]


def _normalise(item: Dict[str, Any], base: str = "") -> Dict[str, Any]:
    fname = item.get("filename", "")
    if base and fname.startswith(base):
        fname = os.path.relpath(fname, base)
    return {
        "test_id": item.get("test_id"),
        "test_name": item.get("test_name"),
        "issue_text": item.get("issue_text"),
        "severity": item.get("issue_severity"),
        "confidence": item.get("issue_confidence"),
        "line_number": item.get("line_number"),
        "line_range": item.get("line_range"),
        "cwe": (item.get("issue_cwe") or {}).get("id"),
        "filename": fname,
    }


def run_bandit_scan(code: str) -> List[Dict[str, Any]]:
    """Scan a code snippet; returns normalised findings (empty list = clean)."""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as fh:
        fh.write(code or "")
        path = fh.name
    try:
        r = subprocess.run(_bandit_cmd() + ["-f", "json", "-q", path], capture_output=True, text=True, timeout=60)
        if not r.stdout.strip():
            return []
        data = json.loads(r.stdout)
        return [_normalise(i) for i in data.get("results", [])]
    except Exception as exc:  # keep the pipeline alive
        return [{"test_id": "ERROR", "issue_text": f"Bandit execution failed: {exc}", "severity": "LOW",
                 "confidence": "LOW", "line_number": None}]
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def scan_path(path: str, excludes: str = ".git,node_modules,.venv,venv,tests,test,site-packages") -> List[Dict[str, Any]]:
    """Recursively scan a directory (repo mode)."""
    cmd = _bandit_cmd() + ["-r", path, "-f", "json", "-q", "-x", ",".join(os.path.join(path, e) for e in excludes.split(","))]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if not r.stdout.strip():
        return []
    data = json.loads(r.stdout)
    return [_normalise(i, base=path.rstrip("/") + "/") for i in data.get("results", [])]


def _key(f: Dict[str, Any]) -> str:
    return str(f.get("test_id"))


def compare(before: List[Dict[str, Any]], after: List[Dict[str, Any]]) -> Dict[str, Any]:
    """SAST oracle verdict for a patch.

    Line numbers shift after a rewrite, so findings are matched by Bandit rule id
    (with multiplicity): a rule that fired N times before must fire fewer times after.

      resolved   - original rule occurrences that disappeared
      remaining  - original MEDIUM/HIGH rule occurrences still present (gating)
      remaining_low - original LOW findings still present (reported, not gating)
      introduced - MEDIUM/HIGH findings of a rule that did not fire before
      passed     - nothing remaining and nothing serious introduced
    """
    before = [f for f in before if f.get("test_id") not in (None, "ERROR")]
    after = [f for f in after if f.get("test_id") not in (None, "ERROR")]
    counts: Dict[str, int] = {}
    for f in before:
        counts[_key(f)] = counts.get(_key(f), 0) + 1
    after_counts: Dict[str, int] = {}
    for f in after:
        after_counts[_key(f)] = after_counts.get(_key(f), 0) + 1

    remaining, remaining_low, introduced = [], [], []
    seen: Dict[str, int] = {}
    for f in after:
        k = _key(f)
        if k in counts:
            seen[k] = seen.get(k, 0) + 1
            if seen[k] <= counts[k]:
                (remaining if SEVERITY_RANK.get(str(f.get("severity")), 0) >= 2 else remaining_low).append(f)
        elif SEVERITY_RANK.get(str(f.get("severity")), 0) >= 2:
            introduced.append(f)
    resolved = sum(max(0, n - after_counts.get(k, 0)) for k, n in counts.items())
    return {
        "passed": not remaining and not introduced,
        "resolved": resolved,
        "remaining": remaining,
        "remaining_low": remaining_low,
        "introduced": introduced,
        "before_count": len(before),
        "after_count": len(after),
    }


def risk_score(f: Dict[str, Any]) -> int:
    return SEVERITY_RANK.get(str(f.get("severity")), 0) * 3 + CONFIDENCE_RANK.get(str(f.get("confidence")), 0)
