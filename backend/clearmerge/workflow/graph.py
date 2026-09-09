from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
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
from .policy import evaluate_policy
from ..scanner import ScannerAgent
from ..scanner.agent import report_to_dict
from ..security import SecurityAgent
from ..security.agent import report_to_dict as security_report_to_dict

Node = Callable[[ReviewState], dict[str, Any]]


def build_review_graph(nodes: dict[str, Node] | None = None, checkpointer: Any = None):
    """Build the review StateGraph with injectable node implementations."""
    handlers = default_nodes()
    handlers.update(nodes or {})
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
    return graph.compile(checkpointer=checkpointer)


def default_nodes() -> dict[str, Node]:
    return {
        "initialize_review": initialize_review,
        "check_still_current": identity_node,
        "run_scanner": run_scanner_node,
        "run_security": run_security_node,
        "score_risk": score_risk_node,
        "evaluate_policy": evaluate_policy_node,
        "request_human_approval": request_human_approval,
        "validate_human_decision": validate_human_decision,
        "publish_decision": publish_decision,
        "finalize_review": finalize_review,
        "supersede_review": supersede_review,
        "handle_failure": handle_failure,
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
    return {"status": "running", "current_stage": "validate_human_decision", "approval": decision}


def evaluate_policy_node(state: ReviewState) -> dict[str, Any]:
    decision = evaluate_policy(
        state.get("risk_assessment", {}),
        state.get("security_results", {}),
        state.get("scanner_results", {}),
    )
    return {
        "current_stage": "evaluate_policy",
        "policy_decision": decision,
        "status": "waiting_for_approval" if decision == "require_approval" else "running",
    }


def validate_human_decision(state: ReviewState) -> dict[str, Any]:
    approval = state.get("approval", {})
    if approval.get("commit_sha") != state.get("commit_sha"):
        return {"status": "failed", "current_stage": "validate_human_decision", "errors": [
            {"stage": "validate_human_decision", "code": "stale_approval", "message": "Approval does not match the reviewed commit.", "retryable": False}
        ]}
    if approval.get("reviewer_id") not in state.get("authorized_reviewer_ids", []):
        return {"status": "failed", "current_stage": "validate_human_decision", "errors": [
            {"stage": "validate_human_decision", "code": "unauthorized_reviewer", "message": "Reviewer is not authorized for this repository.", "retryable": False}
        ]}
    status = "approved" if approval.get("decision") == "approve" else "rejected"
    return {"status": status, "current_stage": "validate_human_decision"}


def publish_decision(state: ReviewState) -> dict[str, Any]:
    policy_decision = state.get("policy_decision")
    approval = state.get("approval", {})
    if policy_decision == "require_approval":
        decision = "allow" if approval.get("decision") == "approve" else "block"
    else:
        decision = policy_decision
    conclusion = "success" if decision == "allow" else "failure"
    return {
        "current_stage": "publish_decision",
        "merge_decision": {
            "decision": decision,
            "reason_codes": [],
            "human_approval_required": policy_decision == "require_approval",
            "github_check_conclusion": conclusion,
            "policy_version": "1.0",
            "commit_sha": state.get("commit_sha", ""),
        },
    }


def finalize_review(state: ReviewState) -> dict[str, Any]:
    decision = state.get("merge_decision", {}).get("decision")
    status = "completed" if decision == "allow" else "blocked"
    if state.get("status") in {"failed", "superseded"}:
        status = state["status"]
    return {"status": status, "current_stage": "finalize_review"}


def supersede_review(state: ReviewState) -> dict[str, Any]:
    return {"status": "superseded", "current_stage": "supersede_review"}


def handle_failure(state: ReviewState) -> dict[str, Any]:
    return {"status": "failed", "current_stage": "handle_failure"}


def run_scanner_node(state: ReviewState) -> dict[str, Any]:
    report = ScannerAgent(repo_path=Path(state["repo_path"])).run()
    serialized = report_to_dict(report)
    warnings = [
        finding
        for finding in serialized["findings"]
        if isinstance(finding, dict) and finding["severity"] == "low"
    ]
    return {
        "current_stage": "run_scanner",
        "status": "failed" if report.status.value == "failed" else "running",
        "scanner_results": {**serialized, "warnings": warnings},
    }


def run_security_node(state: ReviewState) -> dict[str, Any]:
    report = SecurityAgent(repo_path=Path(state["repo_path"])).run()
    serialized = security_report_to_dict(report)
    return {
        "current_stage": "run_security",
        "status": "failed" if report.status.value == "failed" else "running",
        "security_results": serialized,
    }


def score_risk_node(state: ReviewState) -> dict[str, Any]:
    scanner_results = state.get("scanner_results", {})
    security_results = state.get("security_results", {})
    scanner_warnings = scanner_results.get("warnings", [])
    security_findings = security_results.get("findings", [])
    security_warnings = security_results.get("warnings", [])
    has_critical = any(
        isinstance(item, dict) and item.get("severity") == "critical"
        for item in security_findings
    )
    if has_critical:
        risk_level = "critical"
    elif scanner_warnings or security_warnings:
        risk_level = "medium"
    else:
        risk_level = "low"
    return {
        "current_stage": "score_risk",
        "status": "running",
        "risk_assessment": {
            "score": 70 if risk_level == "medium" else 10 if risk_level == "low" else 100,
            "risk_level": risk_level,
            "recommendation": "require_approval" if risk_level == "medium" else "block" if risk_level == "critical" else "allow",
            "factors": [*scanner_warnings, *security_warnings],
            "confidence": 1.0,
        },
    }


def identity_node(state: ReviewState) -> dict[str, Any]:
    return state
