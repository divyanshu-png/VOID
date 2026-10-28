"""LLM access with structured (schema-validated) outputs.

The graph only talks to `get_llm()`, so tests and the evaluation harness can
swap in a fake object exposing the same `audit()` / `repair()` methods.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from app.core import config

logging.getLogger("google_genai.models").setLevel(logging.ERROR)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    title: str = Field(description="Short name of the weakness, e.g. 'SQL injection'")
    cwe: str = Field(description="CWE identifier, e.g. 'CWE-89'")
    owasp: str = Field(default="", description="OWASP Top 10 2021 category, e.g. 'A03:2021-Injection'")
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    line: Optional[int] = Field(default=None, description="1-based line number in the original code")
    explanation: str = Field(description="Why this is exploitable, in one or two sentences")
    fix: str = Field(description="What the fix should do, in one or two sentences")


class AuditResult(BaseModel):
    summary: str = Field(description="One-sentence overall assessment")
    findings: List[Finding] = Field(default_factory=list)


class RepairResult(BaseModel):
    patched_code: str = Field(description="The complete fixed program, raw Python, no markdown fences")
    tests: str = Field(description="A pytest test module for the fixed program, raw Python, no markdown fences")
    notes: str = Field(default="", description="One or two sentences on what changed")


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
AUDIT_SYSTEM = (
    "You are a senior application security engineer. You review Python code for "
    "exploitable weaknesses, map each one to a CWE and an OWASP Top 10 (2021) category, "
    "and say how to fix it. Report only real, specific issues in the given code. "
    "Use the static-analysis results as evidence but you may add issues they missed "
    "or dismiss clear false positives."
)

REPAIR_SYSTEM = (
    "You are an automated program-repair engine for security vulnerabilities. You "
    "return a complete fixed program and a pytest test module.\n"
    "Rules for the fixed program:\n"
    "- Fix every listed weakness. Keep all existing function and class names, "
    "signatures and return types so callers keep working. Preserve business logic.\n"
    "- Do not add a __main__ block, input() calls, servers or network calls at import time.\n"
    "- Change only what the fix needs. NEVER wrap imports in try/except, never add fallback "
    "or mock classes to the program, never remove imports. Third-party packages that are not "
    "installed in the test sandbox are replaced automatically with mocks, so the program can "
    "keep its normal imports.\n"
    "Rules for the tests:\n"
    "- The tests are appended to the same module as the program, so call functions "
    "directly; do NOT import the program as a module.\n"
    "- Third-party modules that are not installed (e.g. streamlit, cv2, PIL) are auto-stubbed "
    "with MagicMock; patch them with unittest.mock in tests when you need specific behaviour.\n"
    "- Import pytest and unittest.mock as needed. There is NO network, no database "
    "server and a read-only filesystem except /tmp: mock sockets, HTTP, subprocess and "
    "databases, or use sqlite3 ':memory:' / tmp_path.\n"
    "- Include at least one test that would FAIL on the original vulnerable code "
    "(e.g. an injection payload is treated as data) and at least one test of normal behaviour.\n"
    "Return raw Python only, never markdown fences."
)


def _strip_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:python|py)?\s*\n", "", text)
    text = re.sub(r"\n?```\s*$", "", text)
    return text.replace("```python", "").replace("```", "").strip()


def audit_prompt(code: str, ast_meta: dict, static_issues: list, packages: list) -> str:
    return (
        f"AST summary (imports / functions / classes):\n{json.dumps(ast_meta, default=str)[:3000]}\n\n"
        f"Bandit SAST findings:\n{json.dumps(static_issues, default=str)[:4000]}\n\n"
        f"Package registry checks:\n{json.dumps(packages, default=str)[:2000]}\n\n"
        f"Code (line numbers are 1-based):\n" + _numbered(code)
    )


def repair_prompt(code: str, findings: list, feedback: Optional[str]) -> str:
    parts = [
        "Original code:\n" + code,
        "Audit findings to fix:\n" + json.dumps(findings, default=str, indent=1)[:6000],
    ]
    if feedback:
        parts.append(
            "IMPORTANT - your previous attempt was REJECTED by the verifiers. Fix these problems:\n"
            + feedback[:6000]
        )
    return "\n\n".join(parts)


def _numbered(code: str) -> str:
    return "\n".join(f"{i + 1:>4}| {line}" for i, line in enumerate(code.splitlines()))


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class LLMError(RuntimeError):
    """An LLM failure with a human-readable explanation (shown in the UI)."""


def explain_error(text: str, model: str) -> str:
    if "prepayment credits are depleted" in text or ("402" in text and "RESOURCE_EXHAUSTED" in text):
        return ("Gemini refused the request: the prepaid credits on this API key's Google project are used up. "
                "Top up billing at https://ai.studio/projects, or use a key from another project.")
    if "429" in text or "RESOURCE_EXHAUSTED" in text:
        return "Gemini rate limit / quota reached for this key. Wait a minute or use a key with more quota."
    if "NOT_FOUND" in text and "model" in text.lower():
        hint = re.search(r"use models/([\w.-]+)", text)
        suggestion = f" Google suggests GEMINI_MODEL={hint.group(1)}." if hint else ""
        return f"Model '{model}' is not available to this key. Change GEMINI_MODEL in backend/.env.{suggestion}"
    if "API_KEY_SERVICE_BLOCKED" in text or "PERMISSION_DENIED" in text:
        return ("This API key is not allowed to call Gemini (it is restricted to other Google APIs). "
                "Create a Gemini API key at https://aistudio.google.com/apikey.")
    if "API key not valid" in text or "API_KEY_INVALID" in text:
        return "The GEMINI_API_KEY in backend/.env is not valid."
    return f"Gemini call failed: {text[:400]}"


class GeminiClient:
    """Thin wrapper around langchain-google-genai with usage accounting."""

    # Endpoint that worked last, shared across clients so the probe happens once per server run.
    _endpoint: Optional[bool] = None

    def __init__(self, model: Optional[str] = None, temperature: Optional[float] = None):
        self.model_name = model or config.GEMINI_MODEL
        self._temperature = config.LLM_TEMPERATURE if temperature is None else temperature
        self._key = config.require_api_key()
        vertex = GeminiClient._endpoint if GeminiClient._endpoint is not None else config.USE_VERTEXAI
        self._llm = self._make(vertex)
        self._vertex = vertex
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.seconds = 0.0

    def _make(self, vertex: bool):
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(model=self.model_name, google_api_key=self._key,
                                      temperature=self._temperature, vertexai=vertex)

    def _invoke(self, schema, messages):
        try:
            out = self._llm.with_structured_output(schema, include_raw=True).invoke(messages)
            GeminiClient._endpoint = self._vertex
            return out
        except Exception as exc:
            text = str(exc)
            # A key restricted to the other Google endpoint: switch once, unless the
            # user forced an endpoint with GOOGLE_GENAI_USE_VERTEXAI.
            wrong_endpoint = any(s in text for s in ("API_KEY_SERVICE_BLOCKED", "API key not valid",
                                                     "API_KEY_INVALID", "SERVICE_DISABLED"))
            if wrong_endpoint and GeminiClient._endpoint is None and os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "auto") == "auto":
                self._vertex = not self._vertex
                self._llm = self._make(self._vertex)
                out = self._llm.with_structured_output(schema, include_raw=True).invoke(messages)
                GeminiClient._endpoint = self._vertex
                return out
            raise

    def _structured(self, schema, system: str, user: str):
        from langchain_core.messages import HumanMessage, SystemMessage

        started = time.time()
        try:
            out = self._invoke(schema, [SystemMessage(content=system), HumanMessage(content=user)])
        except Exception as exc:
            raise LLMError(explain_error(str(exc), self.model_name)) from exc
        self.seconds += time.time() - started
        self.calls += 1
        raw = out.get("raw")
        usage = getattr(raw, "usage_metadata", None) or {}
        self.input_tokens += int(usage.get("input_tokens", 0) or 0)
        self.output_tokens += int(usage.get("output_tokens", 0) or 0)
        parsed = out.get("parsed")
        if parsed is None and raw is not None:
            parsed = self._fallback_parse(schema, getattr(raw, "content", ""))
        return parsed

    @staticmethod
    def _fallback_parse(schema, content):
        if isinstance(content, list):
            content = "".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in content)
        content = content or ""
        m = re.search(r"\{.*\}", content, flags=re.S)
        if m:
            try:
                return schema.model_validate(json.loads(m.group(0)))
            except Exception:
                pass
        if schema is RepairResult and "---TEST_SPLIT---" in content:
            code, tests = content.split("---TEST_SPLIT---", 1)
            return RepairResult(patched_code=_strip_fences(code), tests=_strip_fences(tests))
        return None

    def audit(self, code: str, ast_meta: dict, static_issues: list, packages: list) -> AuditResult:
        res = self._structured(AuditResult, AUDIT_SYSTEM, audit_prompt(code, ast_meta, static_issues, packages))
        return res or AuditResult(summary="Audit could not be parsed.", findings=[])

    def repair(self, code: str, findings: list, feedback: Optional[str]) -> RepairResult:
        res = self._structured(RepairResult, REPAIR_SYSTEM, repair_prompt(code, findings, feedback))
        if res is None:
            return RepairResult(patched_code=code, tests="", notes="Repair output could not be parsed.")
        res.patched_code = _strip_fences(res.patched_code)
        res.tests = _strip_fences(res.tests)
        return res

    def usage(self) -> dict:
        return {
            "llm_calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "llm_seconds": round(self.seconds, 2),
            "model": self.model_name,
            "endpoint": "vertex-ai" if self._vertex else "gemini-api",
        }


_factory = None


def set_llm_factory(factory) -> None:
    """Override how LLM clients are created (used by tests and the eval harness)."""
    global _factory
    _factory = factory


def get_llm():
    if _factory:
        return _factory()
    if config.STUB_LLM:
        from app.core.stub_llm import StubLLM
        return StubLLM()
    return GeminiClient()
