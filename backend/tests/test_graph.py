from dotenv import load_dotenv

# Load environment before any tests run
load_dotenv()

from types import SimpleNamespace

import pytest
from app.tools.ast_parser import parse_code_structure
from app.tools.pypi_validator import verify_packages
from app.core.sandbox import execute_in_sandbox
from app.graph.workflow import agent_graph
import app.graph.workflow as workflow_module

def test_ast_parser_extracts_imports_and_functions():
    code = """
import os
import sqlite3

def fetch_data(query):
    pass
"""
    result = parse_code_structure(code)
    assert result["valid_syntax"] is True
    assert "sqlite3" in result["imports"]
    assert len(result["functions"]) == 1
    assert result["functions"][0]["name"] == "fetch_data"

def test_pypi_validator_flags_fake_package(monkeypatch):
    class NotFoundResponse:
        status_code = 404

    monkeypatch.setattr(
        "app.tools.pypi_validator.requests.get",
        lambda *_args, **_kwargs: NotFoundResponse(),
    )
    fake_pkg = ["non_existent_fake_package_xyz_999"]
    alerts = verify_packages(fake_pkg)
    assert len(alerts) == 1
    assert alerts[0]["package"] == "non_existent_fake_package_xyz_999"

def test_sandbox_executes_valid_code():
    code = "def add(a, b): return a + b"
    test_code = "def test_add(): assert add(2, 3) == 5"
    passed, logs = execute_in_sandbox(code, test_code)
    assert passed is True
    assert logs is None

def test_full_pipeline_vulnerable_code(monkeypatch):
    # Keep the regular test suite independent of Gemini credentials/network access.
    responses = iter([
        "SQL injection risk: use a parameterized query.",
        """def get_user(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cursor.fetchall()
---TEST_SPLIT---
class FakeCursor:
    def execute(self, query, params):
        self.query = query
        self.params = params

    def fetchall(self):
        return [("user",)]

def test_get_user_uses_parameterized_query():
    cursor = FakeCursor()
    assert get_user(cursor, "' OR 1=1 --") == [("user",)]
    assert cursor.query == "SELECT * FROM users WHERE id = ?"
    assert cursor.params == ("' OR 1=1 --",)
""",
    ])

    class FakeLLM:
        def invoke(self, _messages):
            return SimpleNamespace(content=next(responses))

    monkeypatch.setattr(workflow_module, "llm", FakeLLM())

    vulnerable_snippet = """
import sqlite3

def get_user(uid):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{uid}'")
    return cursor.fetchall()
"""
    initial_state = {
        "original_code": vulnerable_snippet,
        "file_language": "python",
        "ast_metadata": {},
        "static_issues": [],
        "security_audit": [],
        "refactored_code": None,
        "generated_tests": None,
        "test_execution_status": "PENDING",
        "error_logs": None,
        "retry_count": 0,
        "final_diff": None,
    }
    result = agent_graph.invoke(initial_state)
    assert result["ast_metadata"]["valid_syntax"] is True
    assert result["refactored_code"] is not None
    assert result["final_diff"] is not None
