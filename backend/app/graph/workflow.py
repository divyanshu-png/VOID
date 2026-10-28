"""LangGraph assembly.

    precheck -> security_audit -> refactor -> sandbox --(rejected & retries left)--> refactor
                                                       \\--(accepted / budget spent)--> presentation
"""
from __future__ import annotations

from typing import Any, Dict, Iterator, Optional, Tuple

from langgraph.graph import END, StateGraph

from app.core import config as settings
from app.graph.nodes import (
    MODES, audit_node, precheck_node, presentation_node, refactor_node, route_after_audit,
    route_after_precheck, route_after_sandbox, sandbox_verification_node,
)
from app.graph.state import AgentCodeState, initial_state

NODE_ORDER = ["ast_parser", "security_audit", "refactor", "sandbox", "presentation"]


def build_graph():
    g = StateGraph(AgentCodeState)
    g.add_node("ast_parser", precheck_node)
    g.add_node("security_audit", audit_node)
    g.add_node("refactor", refactor_node)
    g.add_node("sandbox", sandbox_verification_node)
    g.add_node("presentation", presentation_node)

    g.set_entry_point("ast_parser")
    g.add_conditional_edges("ast_parser", route_after_precheck,
                            {"security_audit": "security_audit", "presentation": "presentation"})
    g.add_conditional_edges("security_audit", route_after_audit,
                            {"refactor": "refactor", "presentation": "presentation"})
    g.add_edge("refactor", "sandbox")
    g.add_conditional_edges("sandbox", route_after_sandbox,
                            {"refactor": "refactor", "presentation": "presentation"})
    g.add_edge("presentation", END)
    return g.compile()


agent_graph = build_graph()


def _cfg(llm) -> Dict[str, Any]:
    # One client per run, so usage counters (calls, tokens) cover the whole review.
    if llm is None:
        from app.core.llm import get_llm
        llm = get_llm()
    return {"recursion_limit": 50, "configurable": {"llm": llm}}


def _check_mode(mode: str) -> str:
    if mode not in MODES:
        raise ValueError(f"oracle_mode must be one of {MODES}")
    return mode


def run_review(code: str, language: str = "python", oracle_mode: Optional[str] = None,
               max_retries: Optional[int] = None, llm=None, local_modules=None) -> AgentCodeState:
    mode = _check_mode(oracle_mode or settings.ORACLE_MODE)
    state = initial_state(code, language, mode, max_retries or settings.MAX_RETRIES, local_modules)
    return agent_graph.invoke(state, _cfg(llm))


def stream_review(code: str, language: str = "python", oracle_mode: Optional[str] = None,
                  max_retries: Optional[int] = None, llm=None, local_modules=None) -> Iterator[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    """Yield (node_name, node_update, merged_state) after every node."""
    mode = _check_mode(oracle_mode or settings.ORACLE_MODE)
    state: Dict[str, Any] = dict(initial_state(code, language, mode, max_retries or settings.MAX_RETRIES, local_modules))
    for chunk in agent_graph.stream(state, _cfg(llm), stream_mode="updates"):
        for node, update in chunk.items():
            update = update or {}
            state.update(update)
            yield node, update, state
