import difflib
from langgraph.graph import StateGraph, END
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage

from app.core.config import GEMINI_API_KEY
from app.graph.state import AgentCodeState
from app.tools.ast_parser import parse_code_structure
from app.tools.sast_scanner import run_bandit_scan
from app.tools.pypi_validator import verify_packages
from app.core.sandbox import execute_in_sandbox

llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    api_key=GEMINI_API_KEY,
    temperature=0.1
)

def parse_ast_node(state: AgentCodeState) -> AgentCodeState:
    code = state["original_code"]
    ast_info = parse_code_structure(code)
    state["ast_metadata"] = ast_info
    
    # Deterministic SAST & Package Registry checks
    static_issues = run_bandit_scan(code)
    suspicious_pkgs = verify_packages(ast_info.get("imports", []))
    state["static_issues"] = static_issues + suspicious_pkgs
    return state

def security_audit_node(state: AgentCodeState) -> AgentCodeState:
    prompt = f"""
    Review this Python code for OWASP Top 10 vulnerabilities, bad practices, and security flaws.
    AST Discovered Imports: {state['ast_metadata'].get('imports', [])}
    Deterministic Scanner Alerts: {state.get('static_issues', [])}

    Code:
    ```python
    {state['original_code']}
    ```
    Return a bulleted list describing each flaw, its security risk, and the necessary fix.
    """
    response = llm.invoke([
        SystemMessage(content="You are a senior Application Security Engineer specializing in vulnerability analysis."),
        HumanMessage(content=prompt)
    ])
    state["security_audit"] = [{"issue": response.content}]
    return state

def refactor_node(state: AgentCodeState) -> AgentCodeState:
    error_context = (
        f"\nCRITICAL: The previous patch failed tests with:\n{state.get('error_logs')}\nEnsure this issue is fixed."
        if state.get("error_logs") else ""
    )

    prompt = f"""
    Refactor the following code to fix all identified security vulnerabilities while preserving original business logic.
    Also generate a companion pytest test suite validating the refactored code.
    {error_context}

    Original Code:
    {state['original_code']}

    Audit Findings:
    {state['security_audit']}

    Output format instructions:
    Separate the refactored code and the test suite using:
    ---TEST_SPLIT---
    Do not use markdown code block syntax (```python or ```). Output raw Python code only.
    Section 1: Refactored Code
    Section 2: Pytest Suite
    """
    response = llm.invoke([
        SystemMessage(content="You are an autonomous code refactoring engine. Return only clean executable Python code."),
        HumanMessage(content=prompt)
    ])

    raw_text = response.content.replace("```python", "").replace("```", "").strip()
    parts = raw_text.split("---TEST_SPLIT---")

    state["refactored_code"] = parts[0].strip()
    state["generated_tests"] = parts[1].strip() if len(parts) > 1 else ""
    state["retry_count"] = state.get("retry_count", 0) + 1
    return state

def sandbox_verification_node(state: AgentCodeState) -> AgentCodeState:
    refactored = state.get("refactored_code", "")
    tests = state.get("generated_tests", "")

    passed, error_output = execute_in_sandbox(refactored, tests)
    state["test_execution_status"] = "PASSED" if passed else "FAILED"
    state["error_logs"] = error_output
    return state

def presentation_node(state: AgentCodeState) -> AgentCodeState:
    orig = state["original_code"].splitlines(keepends=True)
    refactored = (state["refactored_code"] or "").splitlines(keepends=True)
    diff = difflib.unified_diff(orig, refactored, fromfile="original.py", tofile="refactored.py")
    state["final_diff"] = "".join(diff)
    return state

def route_after_sandbox(state: AgentCodeState) -> str:
    if state["test_execution_status"] == "PASSED" or state["retry_count"] >= 3:
        return "presentation"
    return "refactor"

# Construct graph
workflow = StateGraph(AgentCodeState)
workflow.add_node("ast_parser", parse_ast_node)
workflow.add_node("security_audit", security_audit_node)
workflow.add_node("refactor", refactor_node)
workflow.add_node("sandbox", sandbox_verification_node)
workflow.add_node("presentation", presentation_node)

workflow.set_entry_point("ast_parser")
workflow.add_edge("ast_parser", "security_audit")
workflow.add_edge("security_audit", "refactor")
workflow.add_edge("refactor", "sandbox")
workflow.add_conditional_edges("sandbox", route_after_sandbox, {
    "presentation": "presentation",
    "refactor": "refactor"
})
workflow.add_edge("presentation", END)

agent_graph = workflow.compile()