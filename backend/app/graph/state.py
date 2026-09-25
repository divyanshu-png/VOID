from typing import TypedDict, List, Dict, Optional

class AgentCodeState(TypedDict):
    original_code: str
    file_language: str
    ast_metadata: Dict
    static_issues: List[Dict]
    security_audit: List[Dict]
    refactored_code: Optional[str]
    generated_tests: Optional[str]
    test_execution_status: str       # "PASSED", "FAILED", "PENDING"
    error_logs: Optional[str]
    retry_count: int
    final_diff: Optional[str]