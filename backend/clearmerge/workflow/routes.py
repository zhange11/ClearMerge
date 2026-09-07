from __future__ import annotations

from typing import Literal

from .state import ReviewState


Route = Literal[
    "run_scanner",
    "run_security",
    "score_risk",
    "request_human_approval",
    "publish_decision",
    "supersede_review",
    "handle_failure",
    "finalize_review",
]


def route_after_current_check(state: ReviewState) -> Route:
    if state.get("latest_commit_sha", state.get("commit_sha")) != state.get("commit_sha"):
        return "supersede_review"
    return "run_scanner"


def route_after_scanner(state: ReviewState) -> Route:
    return "handle_failure" if state.get("status") == "failed" else "run_security"


def route_after_security(state: ReviewState) -> Route:
    return "handle_failure" if state.get("status") == "failed" else "score_risk"


def route_after_policy(state: ReviewState) -> Route:
    decision = state.get("policy_decision")
    if decision == "require_approval":
        return "request_human_approval"
    if decision in {"allow", "block"}:
        return "publish_decision"
    return "handle_failure"


def route_after_human_decision(state: ReviewState) -> Route:
    approval = state.get("approval", {})
    if state.get("latest_commit_sha", state.get("commit_sha")) != state.get("commit_sha"):
        return "supersede_review"
    if approval.get("commit_sha") != state.get("commit_sha"):
        return "handle_failure"
    if approval.get("decision") in {"approve", "reject"}:
        return "publish_decision"
    return "handle_failure"


def route_after_failure(state: ReviewState) -> Route:
    attempts = state.get("attempts", {}).get(state.get("current_stage", ""), 0)
    return "handle_failure" if attempts >= 3 else state.get("current_stage", "finalize_review")  # type: ignore[return-value]
