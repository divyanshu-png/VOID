import pytest
from app.graph.workflow import agent_graph

def test_full_pipeline_vulnerable_code():
    vulnerable_snippet = """
import sqlite3

def get_user_records(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
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
    assert "sqlite3" in result["ast_metadata"]["imports"]
    assert len(result["security_audit"]) > 0
    assert result["refactored_code"] is not None
    assert result["final_diff"] is not None
    assert result["retry_count"] >= 1