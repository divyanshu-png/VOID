from fastapi import APIRouter, HTTPException
from app.api.schemas import AuditRequest, AuditResponse
from app.graph.workflow import agent_graph

router = APIRouter()

@router.post("/audit", response_model=AuditResponse)
async def review_code(payload: AuditRequest):
    if not payload.code.strip():
        raise HTTPException(status_code=400, detail="Source code payload cannot be empty.")

    initial_state = {
        "original_code": payload.code,
        "file_language": payload.language,
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

    try:
        # Executes the state graph until END is reached
        final_state = agent_graph.invoke(initial_state)

        return AuditResponse(
            status="SUCCESS",
            audit_notes=final_state.get("security_audit", []),
            refactored_code=final_state.get("refactored_code"),
            diff=final_state.get("final_diff"),
            test_status=final_state.get("test_execution_status", "UNKNOWN"),
            retries=final_state.get("retry_count", 0),
            error_logs=final_state.get("error_logs")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent runtime failure: {str(e)}")