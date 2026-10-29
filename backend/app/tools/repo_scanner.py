"""Repo mode: clone a GitHub repository, rank its riskiest code blocks with Bandit,
and turn each one into a self-contained snippet the agent can repair."""
from __future__ import annotations

import hashlib
import os
import random
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import requests

from app.core import config
from app.tools.ast_parser import extract_enclosing
from app.tools.sast_scanner import SEVERITY_RANK, risk_score, scan_path

# Deliberately vulnerable Python projects that are good for demos.
DEMO_REPOS = [
    "https://github.com/stamparm/DSVW",
    "https://github.com/we45/Vulnerable-Flask-App",
    "https://github.com/anxolerd/dvpwa",
    "https://github.com/adeyosemanputra/pygoat",
]

_GH = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


def parse_github_url(url: str) -> tuple[str, str]:
    m = _GH.search(url.strip())
    if not m:
        raise ValueError("Expected a GitHub URL like https://github.com/owner/repo")
    return m.group(1), m.group(2)


def clone(url: str, refresh: bool = False) -> Path:
    owner, repo = parse_github_url(url)
    config.REPO_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    dest = config.REPO_CACHE_DIR / f"{owner}__{repo}"
    if dest.exists() and refresh:
        shutil.rmtree(dest, ignore_errors=True)
    if not dest.exists():
        r = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", f"https://github.com/{owner}/{repo}.git", str(dest)],
            capture_output=True, text=True, timeout=180,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if r.returncode != 0:
            raise RuntimeError(f"git clone failed: {r.stderr.strip()[:300]}")
    return dest


def local_modules(root: Path) -> Set[str]:
    """Top-level importable names inside the repo, so they are not checked against PyPI."""
    names: Set[str] = set()
    for p in root.rglob("*.py"):
        if any(part in {".git", "node_modules", ".venv", "venv"} for part in p.parts):
            continue
        rel = p.relative_to(root).parts
        for i in range(len(rel)):
            names.add(Path(rel[i]).stem)
    return names


LANG_EXT = {".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript", ".jsx": "JavaScript",
            ".java": "Java", ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".rs": "Rust", ".kt": "Kotlin",
            ".c": "C", ".cpp": "C++", ".swift": "Swift"}


def languages(root: Path) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for p in root.rglob("*"):
        if p.is_file() and not any(x in {".git", "node_modules", ".venv", "venv", "dist", "build"} for x in p.parts):
            lang = LANG_EXT.get(p.suffix.lower())
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def scan_repo(url: str, min_severity: str = "MEDIUM", limit: int = 25, refresh: bool = False) -> Dict[str, Any]:
    root = clone(url, refresh=refresh)
    langs = languages(root)
    if not langs.get("Python"):
        found = ", ".join(f"{k} ({v} files)" for k, v in list(langs.items())[:3]) or "no source files"
        raise ValueError(f"This repository has no Python files (found {found}). VOID currently reviews Python only; "
                         "JavaScript/TypeScript support is planned work.")
    findings = scan_path(str(root))
    floor = SEVERITY_RANK.get(min_severity.upper(), 2)
    targets: Dict[str, Dict[str, Any]] = {}
    py_files = sum(1 for _ in root.rglob("*.py"))
    for f in findings:
        if SEVERITY_RANK.get(str(f.get("severity")), 0) < floor:
            continue
        path = root / f["filename"]
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        info = extract_enclosing(code, int(f.get("line_number") or 0))
        if not info or info["end_line"] - info["start_line"] > 150:
            continue
        key = f"{f['filename']}::{info['name']}::{info['start_line']}"
        t = targets.setdefault(key, {
            "id": hashlib.sha1(key.encode()).hexdigest()[:10],
            "file": f["filename"], "name": info["name"], "kind": info["kind"],
            "start_line": info["start_line"], "end_line": info["end_line"],
            "snippet": info["snippet"], "findings": [], "score": 0,
        })
        t["findings"].append({k: f.get(k) for k in ("test_id", "issue_text", "severity", "confidence", "line_number", "cwe")})
        t["score"] += risk_score(f)
    ranked = sorted(targets.values(), key=lambda t: -t["score"])[:limit]
    owner, repo = parse_github_url(url)
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[str(f.get("severity"))] = sev_counts.get(str(f.get("severity")), 0) + 1
    return {
        "repo": f"{owner}/{repo}", "url": url, "python_files": py_files,
        "total_findings": len(findings), "by_severity": sev_counts, "languages": langs,
        "targets": ranked, "local_modules": sorted(local_modules(root)),
    }


def random_repo(user: Optional[str] = None) -> str:
    """A random public, non-fork Python repo of `user`, or a random demo repo."""
    if not user:
        return random.choice(DEMO_REPOS)
    headers = {"Accept": "application/vnd.github+json"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"
    r = requests.get(f"https://api.github.com/users/{user}/repos", params={"per_page": 100, "type": "owner"},
                     headers=headers, timeout=10)
    r.raise_for_status()
    repos = [x for x in r.json() if x.get("language") == "Python" and not x.get("fork") and x.get("size", 0) > 0]
    if not repos:
        raise ValueError(f"No public Python repositories found for '{user}'")
    return random.choice(repos)["html_url"]
