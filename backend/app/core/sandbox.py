"""Execution oracle: runs candidate code + tests in isolation.

Two backends:
  * docker      - a fresh, throwaway container per run: no network, no secrets,
                  capped CPU / memory / processes, read-only filesystem, non-root.
  * subprocess  - development fallback when Docker is not available: separate
                  process with a scrubbed environment (no API keys), CPU/memory
                  rlimits and a hard timeout. NOT a security boundary.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Optional

from app.core import config

_DOCKER_OK: Optional[bool] = None


@dataclass
class ExecResult:
    passed: bool
    status: str  # passed | failed | no_tests | timeout | error
    error_kind: Optional[str] = None  # syntax | runtime | assertion | timeout | None
    logs: str = ""
    backend: str = "subprocess"
    duration_s: float = 0.0
    tests_collected: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def docker_available() -> bool:
    """True if the docker CLI exists, the daemon answers and the sandbox image is built."""
    global _DOCKER_OK
    if _DOCKER_OK is not None:
        return _DOCKER_OK
    if not shutil.which("docker"):
        _DOCKER_OK = False
        return False
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", config.SANDBOX_IMAGE],
            capture_output=True, text=True, timeout=8,
        )
        _DOCKER_OK = r.returncode == 0
    except Exception:
        _DOCKER_OK = False
    return _DOCKER_OK


def active_backend() -> str:
    mode = config.SANDBOX_MODE
    if mode == "docker":
        return "docker"
    if mode == "subprocess":
        return "subprocess"
    return "docker" if docker_available() else "subprocess"


def _compose(code: str, tests: str) -> str:
    return f"{code}\n\n# ---- generated tests ----\n{tests}\n"


def classify(exit_code: int, output: str) -> tuple[str, Optional[str]]:
    """Map pytest exit code + output to (status, error_kind)."""
    if exit_code == 0:
        return "passed", None
    if exit_code == 5:
        return "no_tests", None
    if re.search(r"\b(SyntaxError|IndentationError|TabError)\b", output):
        return "failed", "syntax"
    errors = re.findall(r"^E\s+(\w+(?:Error|Exception))\b", output, flags=re.M)
    non_assert = [e for e in errors if e != "AssertionError"]
    if non_assert:
        return "failed", "runtime"
    if "AssertionError" in output or re.search(r"^E\s+assert ", output, flags=re.M):
        return "failed", "assertion"
    if exit_code == 2:  # collection / import error
        return "failed", "runtime"
    return "failed", "runtime"


def _collected(output: str) -> int:
    return sum(int(n) for n, _ in re.findall(r"(\d+) (passed|failed|errors?)\b", output))


def _syntax_precheck(source: str) -> Optional[str]:
    try:
        compile(source, "test_candidate.py", "exec")
        return None
    except SyntaxError as exc:
        return f"SyntaxError: line {exc.lineno}: {exc.msg}"


def _run_docker(workdir: str, timeout: int) -> tuple[int, str, bool]:
    name = f"void-sbx-{uuid.uuid4().hex[:10]}"
    cmd = [
        "docker", "run", "--rm", "--name", name,
        "--network", "none",
        "--memory", f"{config.SANDBOX_MEMORY_MB}m", "--memory-swap", f"{config.SANDBOX_MEMORY_MB}m",
        "--cpus", "0.5",
        "--pids-limit", "64",
        "--read-only", "--tmpfs", "/tmp:rw,size=64m",
        "--user", "65534:65534",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", f"{workdir}:/work:ro",
        "-w", "/work",
        config.SANDBOX_IMAGE,
        "python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short", "test_candidate.py",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        return r.returncode, (r.stdout or "") + (r.stderr or ""), False
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", name], capture_output=True)
        return -1, "", True


def _limits():  # pragma: no cover - runs in the child process
    try:
        import resource

        cpu = config.SANDBOX_TIMEOUT + 1
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        mem = config.SANDBOX_MEMORY_MB * 1024 * 1024 * 4  # address space is larger than RSS
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        except (ValueError, OSError):
            pass  # not enforced on macOS
        resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    except Exception:
        pass


def _run_subprocess(workdir: str, timeout: int) -> tuple[int, str, bool]:
    # Scrubbed environment: nothing from the server process (API keys etc.) leaks in.
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": workdir,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "LANG": "C.UTF-8",
    }
    preexec = _limits if os.name == "posix" else None
    try:
        p = subprocess.Popen(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short", "test_candidate.py"],
            cwd=workdir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            preexec_fn=preexec, start_new_session=(os.name == "posix"),
        )
    except Exception as exc:
        return -2, f"Sandbox launch error: {exc}", False
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out or "", False
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(p.pid, 9)
            else:
                p.kill()
        except Exception:
            p.kill()
        p.communicate()
        return -1, "", True


def execute_in_sandbox(code: str, tests: str, timeout: Optional[int] = None) -> ExecResult:
    """Run `tests` against `code` (concatenated into one module) and classify the outcome."""
    timeout = timeout or config.SANDBOX_TIMEOUT
    backend = active_backend()
    source = _compose(code or "", tests or "")

    if not (tests or "").strip():
        return ExecResult(False, "no_tests", None, "No tests were generated.", backend)

    syntax = _syntax_precheck(source)
    if syntax:
        return ExecResult(False, "failed", "syntax", syntax, backend)

    started = time.time()
    with tempfile.TemporaryDirectory(prefix="void_sbx_") as workdir:
        os.chmod(workdir, 0o755)
        path = os.path.join(workdir, "test_candidate.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(source)
        os.chmod(path, 0o644)
        runner = _run_docker if backend == "docker" else _run_subprocess
        code_rc, output, timed_out = runner(workdir, timeout)

    duration = round(time.time() - started, 3)
    if timed_out:
        return ExecResult(False, "timeout", "timeout",
                          f"Sandbox timed out after {timeout}s (possible infinite loop or blocking call).",
                          backend, duration)
    if code_rc == -2:
        return ExecResult(False, "error", "runtime", output, backend, duration)

    status, kind = classify(code_rc, output)
    return ExecResult(status == "passed", status, kind, output[-6000:], backend, duration, _collected(output))
