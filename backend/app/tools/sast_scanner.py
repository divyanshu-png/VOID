import tempfile
import subprocess
import json
import os
from typing import List, Dict, Any

def run_bandit_scan(code: str) -> List[Dict[str, Any]]:
    """
    Runs Bandit static analysis on a code snippet via an ephemeral file.
    Returns structured security warnings.
    """
    issues: List[Dict[str, Any]] = []

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as temp_file:
        temp_file.write(code)
        temp_file_path = temp_file.name

    try:
        cmd = ["bandit", "-f", "json", "-q", temp_file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stdout:
            data = json.loads(result.stdout)
            for item in data.get("results", []):
                issues.append({
                    "test_id": item.get("test_id"),
                    "issue_text": item.get("issue_text"),
                    "severity": item.get("issue_severity"),
                    "confidence": item.get("issue_confidence"),
                    "line_number": item.get("line_number")
                })
    except Exception as exc:
        issues.append({"error": f"Bandit execution failed: {str(exc)}"})
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

    return issues