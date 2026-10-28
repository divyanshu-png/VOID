"""Offline test suite: no API key, no network required (PyPI is stubbed)."""
from types import SimpleNamespace

import pytest

from app.core.llm import AuditResult, CriticResult, Finding, RepairResult, SupervisorDecision
from app.core.sandbox import execute_in_sandbox
from app.graph.workflow import run_review, stream_review
from app.tools import pypi_validator
from app.tools.ast_parser import extract_enclosing, merge_patch_into_file, parse_code_structure
from app.tools.pypi_validator import check_imports, lookalike, resolve_distribution, verify_packages
from app.tools.sast_scanner import compare, run_bandit_scan

VULN = '''import sqlite3

def get_user(cursor, uid):
    cursor.execute(f"SELECT * FROM users WHERE id = '{uid}'")
    return cursor.fetchall()
'''

FIXED = '''import sqlite3

def get_user(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cursor.fetchall()
'''

GOOD_TESTS = '''import sqlite3
def test_payload_is_data():
    c = sqlite3.connect(":memory:").cursor()
    c.execute("create table users(id text)")
    c.execute("insert into users values ('1')")
    assert get_user(c, "' OR 1=1 --") == []
    assert get_user(c, "1") == [("1",)]
'''

TRIVIAL_TESTS = "def test_nothing():\n    assert True\n"


class FakeLLM:
    def __init__(self, repairs):
        self.repairs = list(repairs)
        self.calls = 0
        self.feedback = []

    def audit(self, *a):
        self.calls += 1
        return AuditResult(summary="SQL injection", findings=[Finding(
            title="SQL injection", cwe="CWE-89", severity="HIGH", line=4, explanation="f-string query", fix="parameterise")])

    def repair(self, code, findings, feedback):
        self.calls += 1
        self.feedback.append(feedback)
        return self.repairs.pop(0)

    def usage(self):
        return {"llm_calls": self.calls}


class AutoLLM(FakeLLM):
    """FakeLLM plus scripted critic verdicts and supervisor decisions (autonomous mode)."""

    def __init__(self, repairs, critiques=(), decisions=()):
        super().__init__(repairs)
        self.critiques, self.decisions = list(critiques), list(decisions)
        self.audits = 0
        self.history = []

    def audit(self, *a, feedback=None):
        self.audits += 1
        return super().audit(*a)

    def critique(self, *a):
        self.calls += 1
        return self.critiques.pop(0) if self.critiques else CriticResult(approved=True)

    def decide(self, findings, history, budget_left, reaudits_left):
        self.calls += 1
        self.history.append(history)
        return self.decisions.pop(0)


@pytest.fixture(autouse=True)
def offline_pypi(monkeypatch):
    def fake_get(url, timeout=None):
        name = url.rstrip("/").split("/")[-2]
        if "non_existent" in name or name == "reqeusts":
            return SimpleNamespace(status_code=404)
        return SimpleNamespace(status_code=200, json=lambda: {
            "info": {"name": name, "project_urls": {"Source": "https://github.com/x/y"}},
            "releases": {"1.0": [{"upload_time_iso_8601": "2015-01-01T00:00:00Z"}], "2.0": []}})
    pypi_validator._CACHE.clear()
    monkeypatch.setattr("app.tools.pypi_validator.requests.get", fake_get)


# ------------------------------------------------------------------ tools
def test_ast_parser_extracts_imports_and_functions():
    result = parse_code_structure("import os\nimport sqlite3\nfrom . import local\n\ndef fetch_data(query):\n    pass\n")
    assert result["valid_syntax"] is True
    assert "sqlite3" in result["imports"] and "local" not in result["imports"]
    assert result["functions"][0]["name"] == "fetch_data"


def test_ast_parser_reports_syntax_error():
    assert parse_code_structure("def broken(:\n")["valid_syntax"] is False


def test_extract_and_merge_block():
    code = "import sqlite3\n\ndef ok():\n    return 1\n\n" + VULN.split("\n", 2)[2]
    info = extract_enclosing(code, 7)
    assert info and info["name"] == "get_user" and "import sqlite3" in info["snippet"]
    merged = merge_patch_into_file(code, info, "import sqlite3\nimport logging\n\n" + FIXED.split("\n", 2)[2])
    assert "def ok():" in merged and "?" in merged and "import logging" in merged


def test_import_name_mapping():
    assert resolve_distribution("yaml") == "PyYAML"
    assert resolve_distribution("cv2") == "opencv-python"
    assert resolve_distribution("os.path") is None          # stdlib
    assert resolve_distribution("google.generativeai") == "google-generativeai"


def test_lookalike_detection():
    assert lookalike("reqeusts") == "requests"
    assert lookalike("requests-secure") == "requests"
    assert lookalike("flask") is None


def test_pypi_validator_flags_fake_package():
    alerts = verify_packages(["non_existent_fake_package_xyz_999"])
    assert len(alerts) == 1 and alerts[0]["package"] == "non_existent_fake_package_xyz_999"
    report = check_imports(["yaml", "reqeusts"])
    assert report[0]["status"] == "ok" and report[1]["status"] == "not_found"


def test_sast_compare_gate():
    before = run_bandit_scan(VULN)
    assert any(f["test_id"] == "B608" for f in before)
    assert compare(before, run_bandit_scan(VULN))["passed"] is False
    v = compare(before, run_bandit_scan(FIXED))
    assert v["passed"] is True and v["resolved"] >= 1


# ------------------------------------------------------------------ sandbox
def test_sandbox_executes_valid_code():
    r = execute_in_sandbox("def add(a, b): return a + b", "def test_add(): assert add(2, 3) == 5")
    assert r.passed and r.status == "passed"


def test_sandbox_classifies_failures():
    assert execute_in_sandbox("def f(:", "def test_x(): pass").error_kind == "syntax"
    assert execute_in_sandbox("def f(): return 1", "def test_x(): assert f() == 2").error_kind == "assertion"
    assert execute_in_sandbox("def f(): return undefined_name", "def test_x(): f()").error_kind == "runtime"
    assert execute_in_sandbox("def f(): return 1", "").status == "no_tests"


def test_sandbox_hides_secrets(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "super-secret")
    r = execute_in_sandbox("import os", "def test_env(): assert os.environ.get('GEMINI_API_KEY') is None")
    assert r.passed


def test_sandbox_timeout():
    r = execute_in_sandbox("def spin():\n    while True: pass", "def test_spin(): spin()", timeout=2)
    assert r.status == "timeout"


# ------------------------------------------------------------------ graph / oracle modes
def test_dual_oracle_rejects_self_graded_patch_then_accepts_real_fix():
    llm = FakeLLM([RepairResult(patched_code=VULN, tests=TRIVIAL_TESTS),
                   RepairResult(patched_code=FIXED, tests=GOOD_TESTS)])
    state = run_review(VULN, oracle_mode="dual", llm=llm)
    a1, a2 = state["attempts"]
    assert a1["exec"]["passed"] and not a1["sast"]["passed"] and not a1["accepted"]
    assert "B608" in llm.feedback[1]                     # SAST feedback reached the repair agent
    assert a2["accepted"] and state["verdict"] == "verified"
    assert "?" in state["final_diff"]


def test_exec_only_mode_is_fooled_by_trivial_tests():
    """C2 accepts the unchanged vulnerable code because its own tests pass: the self-grading problem."""
    llm = FakeLLM([RepairResult(patched_code=VULN, tests=TRIVIAL_TESTS)])
    state = run_review(VULN, oracle_mode="exec", llm=llm)
    assert state["attempts"][0]["accepted"] and state["verdict"] == "unverified"


def test_single_mode_makes_one_attempt():
    llm = FakeLLM([RepairResult(patched_code=VULN, tests=TRIVIAL_TESTS)])
    state = run_review(VULN, oracle_mode="single", llm=llm)
    assert state["retry_count"] == 1


def test_retry_budget_is_respected():
    bad = RepairResult(patched_code=VULN, tests=TRIVIAL_TESTS)
    state = run_review(VULN, oracle_mode="dual", max_retries=3, llm=FakeLLM([bad, bad, bad]))
    assert state["retry_count"] == 3 and state["verdict"] == "unverified"


def test_stream_emits_every_stage():
    llm = FakeLLM([RepairResult(patched_code=FIXED, tests=GOOD_TESTS)])
    nodes = [n for n, _, _ in stream_review(VULN, oracle_mode="dual", llm=llm)]
    assert nodes == ["ast_parser", "security_audit", "refactor", "sandbox", "presentation"]


# ------------------------------------------------------------------ autonomous mode (C4)
def test_auto_accepts_only_after_critic_approves():
    llm = AutoLLM([RepairResult(patched_code=FIXED, tests=GOOD_TESTS)])
    nodes = [n for n, _, _ in stream_review(VULN, oracle_mode="auto", llm=llm)]
    assert nodes == ["ast_parser", "security_audit", "refactor", "sandbox", "critic", "supervisor", "presentation"]
    state = run_review(VULN, oracle_mode="auto", llm=AutoLLM([RepairResult(patched_code=FIXED, tests=GOOD_TESTS)]))
    assert state["verdict"] == "verified" and state["attempts"][0]["decision"]["action"] == "accept"


def test_auto_critic_veto_overrides_passing_oracles():
    """Both oracles pass, but the critic sees an out-of-scope change: the supervisor must not accept."""
    llm = AutoLLM([RepairResult(patched_code=FIXED, tests=GOOD_TESTS)] * 2,
                  critiques=[CriticResult(approved=False, issues=["imports wrapped in try/except"])],
                  decisions=[SupervisorDecision(action="repair_code", reason="critic veto", guidance="undo the import change")])
    state = run_review(VULN, oracle_mode="auto", llm=llm)
    a1, a2 = state["attempts"]
    assert a1["sast"]["passed"] and a1["exec"]["passed"] and not a1["accepted"]
    assert "try/except" in llm.feedback[1] and "undo the import change" in llm.feedback[1]
    assert a2["accepted"] and state["verdict"] == "verified"


def test_auto_supervisor_can_rewrite_only_the_tests():
    broken_tests = "def test_wrong():\n    assert get_user is None\n"
    llm = AutoLLM([RepairResult(patched_code=FIXED, tests=broken_tests),
                   RepairResult(patched_code="garbage that must be ignored", tests=GOOD_TESTS)],
                  decisions=[SupervisorDecision(action="repair_tests", reason="code fine, test wrong")])
    state = run_review(VULN, oracle_mode="auto", llm=llm)
    a2 = state["attempts"][1]
    assert a2["action"] == "repair_tests" and a2["patched_code"] == FIXED and state["verdict"] == "verified"


def test_auto_supervisor_reaudit_and_give_up():
    llm = AutoLLM([RepairResult(patched_code=VULN, tests=TRIVIAL_TESTS)] * 3,
                  decisions=[SupervisorDecision(action="reaudit", reason="audit wrong"),
                             SupervisorDecision(action="reaudit", reason="still wrong"),
                             SupervisorDecision(action="give_up", reason="no progress")])
    state = run_review(VULN, oracle_mode="auto", max_retries=3, llm=llm)
    assert llm.audits == 2                                     # second re-audit request is capped
    assert state["attempts"][-1]["decision"]["action"] == "give_up"
    assert state["retry_count"] == 3 and state["verdict"] == "unverified"
    assert llm.history[0][0]["sast_remaining"] == ["B608"]      # supervisor saw the oracle evidence


def test_invalid_input_short_circuits():
    state = run_review("def broken(:\n", llm=FakeLLM([]))
    assert state["verdict"] == "invalid_input"


def test_sandbox_stubs_missing_third_party_modules():
    code = "import streamlit as st\nimport totally_missing_pkg_xyz\n\ndef show(x):\n    st.error(x)\n    return x\n"
    r = execute_in_sandbox(code, "def test_show():\n    assert show(3) == 3\n")
    assert r.passed, r.logs


def test_merge_carries_module_level_helpers():
    f = "import requests\n\ndef fetch(u):\n    return requests.get(u)\n"
    info = extract_enclosing(f, 4)
    patched = ("import requests\nimport logging\nlogger = logging.getLogger(__name__)\n\n"
               "def fetch(u):\n    logger.info(u)\n    return requests.get(u, timeout=5)\n")
    merged = merge_patch_into_file(f, info, patched)
    assert "logger = logging.getLogger(__name__)" in merged and "import logging" in merged
    compile(merged, "m.py", "exec")
