from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

OracleMode = Literal["single", "sast", "exec", "dual"]


class AuditRequest(BaseModel):
    code: str
    language: Optional[str] = "python"
    oracle_mode: Optional[OracleMode] = None
    max_retries: Optional[int] = Field(default=None, ge=1, le=6)
    focus_line: Optional[int] = Field(default=None, ge=1, description="Repair only the block around this line")


class AuditResponse(BaseModel):
    status: str
    verdict: str
    oracle_mode: Optional[str] = None
    audit: Dict[str, Any] = {}
    audit_notes: List[Dict] = []
    sast_before: List[Dict] = []
    package_report: List[Dict] = []
    refactored_code: Optional[str] = None
    generated_tests: Optional[str] = None
    diff: Optional[str] = None
    test_status: str
    sast_status: str = "N/A"
    retries: int
    attempts: List[Dict[str, Any]] = []
    error_logs: Optional[str] = None
    usage: Dict[str, Any] = {}
    focus: Optional[Dict[str, Any]] = None
    merged_file: Optional[str] = None
    replay_id: Optional[str] = None


class ScanRequest(BaseModel):
    code: str


class RepoScanRequest(BaseModel):
    url: str
    min_severity: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    limit: int = Field(default=25, ge=1, le=100)
    refresh: bool = False


class RepoRunRequest(BaseModel):
    url: str
    target_ids: List[str] = []
    max_targets: int = Field(default=5, ge=1, le=20)
    oracle_mode: Optional[OracleMode] = None
    min_severity: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"
