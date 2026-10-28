"""Rule-based stand-in for the LLM, for offline development and UI testing.

Enabled with VOID_STUB_LLM=1. It is NOT an AI: it rewrites a handful of known
insecure patterns with regexes and writes simple tests, so the whole pipeline
(oracles, retries, streaming, UI) can be exercised without an API key. The
/health endpoint and the UI label runs made with it as "stub".
"""
from __future__ import annotations

import re
from typing import List, Optional

from app.core.llm import AuditResult, Finding, RepairResult

RULES = [
    # (bandit id, CWE, title, regex, replacement)
    ("B608", "CWE-89", "SQL injection",
     re.compile(r"""(\.execute\()f(["'])(.*?)'?\{(\w+)\}'?(.*?)\2\)"""),
     lambda m: f'{m.group(1)}{m.group(2)}{m.group(3)}?{m.group(5)}{m.group(2)}, ({m.group(4)},))'),
    ("B506", "CWE-20", "Unsafe YAML deserialisation",
     re.compile(r"yaml\.load\(([^,)]+)(?:,[^)]*)?\)"), lambda m: f"yaml.safe_load({m.group(1)})"),
    ("B602", "CWE-78", "OS command injection",
     re.compile(r"subprocess\.(\w+)\((.+?),\s*shell=True"), lambda m: f"subprocess.{m.group(1)}(shlex.split({m.group(2)}), shell=False"),
    ("B307", "CWE-95", "Code injection via eval",
     re.compile(r"(?<![\w.])eval\("), lambda m: "ast.literal_eval("),
    ("B324", "CWE-327", "Weak hash",
     re.compile(r"hashlib\.(md5|sha1)\("), lambda m: "hashlib.sha256("),
    ("B301", "CWE-502", "Unsafe pickle deserialisation",
     re.compile(r"pickle\.loads?\("), lambda m: "json.loads("),
]

NEEDS_IMPORT = {"B602": "import shlex", "B307": "import ast", "B301": "import json"}


class StubLLM:
    def __init__(self):
        self.calls = 0

    def audit(self, code: str, ast_meta: dict, static_issues: list, packages: list) -> AuditResult:
        self.calls += 1
        findings: List[Finding] = []
        for f in static_issues:
            rule = next((r for r in RULES if r[0] == f.get("test_id")), None)
            findings.append(Finding(
                title=rule[2] if rule else (f.get("test_name") or "Issue"),
                cwe=rule[1] if rule else f"CWE-{f.get('cwe')}",
                severity=f.get("severity") if f.get("severity") in ("LOW", "MEDIUM", "HIGH") else "MEDIUM",
                line=f.get("line_number"), explanation=f.get("issue_text") or "",
                fix="Apply the standard safe alternative for this API."))
        for p in packages:
            if p.get("status") in ("not_found", "suspicious"):
                findings.append(Finding(title="Untrusted dependency", cwe="CWE-1357", severity="HIGH",
                                        explanation="; ".join(p.get("reasons", [])), fix=f"Remove or replace '{p['package']}'."))
        return AuditResult(summary=f"Stub audit: {len(findings)} issue(s) from static analysis.", findings=findings)

    def repair(self, code: str, findings: list, feedback: Optional[str]) -> RepairResult:
        self.calls += 1
        patched, used = code, []
        for rid, _cwe, _t, rx, rep in RULES:
            new = rx.sub(rep, patched)
            if new != patched:
                used.append(rid)
                patched = new
        for rid in used:
            imp = NEEDS_IMPORT.get(rid)
            if imp and imp not in patched:
                patched = imp + "\n" + patched
        names = re.findall(r"^def (\w+)\(", patched, flags=re.M)
        tests = "def test_module_loads():\n" + "".join(f"    assert callable({n})\n" for n in names[:5])
        if not names:
            tests += "    assert True\n"
        return RepairResult(patched_code=patched, tests=tests,
                            notes=f"Stub rewrite applied rules: {', '.join(used) or 'none'}")

    def usage(self) -> dict:
        return {"llm_calls": self.calls, "model": "stub (no LLM)"}
