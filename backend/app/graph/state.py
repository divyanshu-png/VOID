from typing import Any, Dict, List, Optional, TypedDict


class AgentCodeState(TypedDict, total=False):
    # input
    original_code: str
    file_language: str
    oracle_mode: str            # single | sast | exec | dual
    max_retries: int
    local_modules: List[str]    # repo-local import names (skip PyPI checks)
    # deterministic pre-analysis
    ast_metadata: Dict[str, Any]
    static_issues: List[Dict]   # Bandit findings on the original + package alerts (legacy view)
    sast_before: List[Dict]     # Bandit findings on the original code
    package_report: List[Dict]  # one entry per third-party import
    # audit
    audit: Dict[str, Any]       # {"summary": str, "findings": [Finding]}
    security_audit: List[Dict]  # legacy: [{"issue": text}]
    # repair loop
    refactored_code: Optional[str]
    generated_tests: Optional[str]
    repair_notes: str
    attempts: List[Dict[str, Any]]   # one record per repair attempt
    sast_oracle: Dict[str, Any]      # last SAST verdict
    exec_oracle: Dict[str, Any]      # last execution verdict
    test_execution_status: str       # PENDING | PASSED | FAILED
    error_logs: Optional[str]
    retry_count: int
    # result
    verdict: str                     # verified | unverified | clean | invalid_input
    final_diff: Optional[str]
    usage: Dict[str, Any]


def initial_state(code: str, language: str = "python", oracle_mode: str = "dual", max_retries: int = 3,
                  local_modules: Optional[List[str]] = None) -> AgentCodeState:
    return AgentCodeState(
        original_code=code, file_language=language, oracle_mode=oracle_mode, max_retries=max_retries,
        local_modules=list(local_modules or []),
        ast_metadata={}, static_issues=[], sast_before=[], package_report=[],
        audit={}, security_audit=[], refactored_code=None, generated_tests=None, repair_notes="",
        attempts=[], sast_oracle={}, exec_oracle={}, test_execution_status="PENDING",
        error_logs=None, retry_count=0, verdict="", final_diff=None, usage={},
    )
