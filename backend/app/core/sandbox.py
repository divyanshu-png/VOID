import subprocess
import tempfile
import os
from typing import Tuple, Optional

def execute_in_sandbox(refactored_code: str, test_code: str, timeout_seconds: int = 6) -> Tuple[bool, Optional[str]]:
    """
    Writes candidate code and companion tests to a temporary file,
    executes pytest in an isolated subprocess, and enforces a strict timeout.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file_path = os.path.join(temp_dir, "test_candidate.py")
        full_content = f"{refactored_code}\n\n{test_code}"

        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(full_content)

        try:
            result = subprocess.run(
                ["pytest", test_file_path, "-q"],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                cwd=temp_dir
            )
            if result.returncode == 0:
                return True, None
            return False, result.stdout or result.stderr
        except subprocess.TimeoutExpired:
            return False, "Sandbox execution timed out (potential infinite loop or blocking call)."
        except Exception as exc:
            return False, f"Sandbox execution error: {str(exc)}"