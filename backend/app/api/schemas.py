from pydantic import BaseModel
from typing import Optional, List, Dict

class AuditRequest(BaseModel):
    code: str
    language: Optional[str] = "python"

class AuditResponse(BaseModel):
    status: str
    audit_notes: List[Dict]
    refactored_code: Optional[str]
    diff: Optional[str]
    test_status: str
    retries: int
    error_logs: Optional[str]