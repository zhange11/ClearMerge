from __future__ import annotations

from collections.abc import Callable
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from .routes import (
    route_after_current_check,
    route_after_human_decision,
    route_after_policy,
    route_after_scanner,
    route_after_security,
)
from .state import ReviewState

Node = Callable[[ReviewState], dict[str, Any]]


def build_review_graph(nodes: dict[str, Node] | None = None):
    """Build the review StateGraph with injectable node implementations."""
    handlers = nodes or default_nodes()
    graph = StateGraph(ReviewState)
    for name, handler in handlers.items():
        graph.add_node(name, handler)

    graph.add_edge(START, "initialize_review")
    graph.add_edge("initialize_review", "check_still_current")
    graph.add_conditional_edges("check_still_current", route_after_current_check)
    graph.add_conditional_edges("run_scanner", route_after_scanner)
    graph.add_conditional_edges("run_security", route_after_security)
    graph.add_edge("score_risk", "evaluate_policy")
    graph.add_conditional_edges("evaluate_policy", route_after_policy)
    graph.add_edge("request_human_approval", "validate_human_decision")
    graph.add_conditional_edges("validate_human_decision", route_after_human_decision)
    graph.add_edge("publish_decision", "finalize_review")
    graph.add_edge("finalize_review", END)
    graph.add_edge("supersede_review", END)
    graph.add_edge("handle_failure", "finalize_review")
    return graph.compile()


def default_nodes() -> dict[str, Node]:
    return {
        "initialize_review": initialize_review,
        "check_still_current": identity_node,
        "run_scanner": identity_node,
        "run_security": identity_node,
        "score_risk": identity_node,
        "evaluate_policy": identity_node,
        "request_human_approval": request_human_approval,
        "validate_human_decision": identity_node,
        "publish_decision": identity_node,
        "finalize_review": identity_node,
        "supersede_review": identity_node,
        "handle_failure": identity_node,
    }


def initialize_review(state: ReviewState) -> dict[str, Any]:
    return {"status": "running", "current_stage": "initialize_review"}


def request_human_approval(state: ReviewState) -> dict[str, Any]:
    request = {
        "review_id": state.get("review_id"),
        "commit_sha": state.get("commit_sha"),
        "risk_assessment": state.get("risk_assessment", {}),
        "message": "Human approval is required before this pull request can merge.",
    }
    decision = interrupt(request)
    return {"status": "waiting_for_approval", "approval": decision}


def identity_node(state: ReviewState) -> dict[str, Any]:
    return state
