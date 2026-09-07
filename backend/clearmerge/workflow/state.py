from __future__ import annotations

from typing import Literal, NotRequired, TypedDict


ReviewStatus = Literal[
    "queued",
    "running",
    "waiting_for_approval",
    "approved",
    "rejected",
    "completed",
    "blocked",
    "failed",
    "superseded",
]

PolicyDecision = Literal["allow", "require_approval", "block"]
HumanDecision = Literal["approve", "reject"]


class RepositoryContext(TypedDict):
    owner: str
    name: str
    installation_id: int
    pull_request: int


class Approval(TypedDict, total=False):
    decision: HumanDecision
    reviewer_id: int
    comment: str
    commit_sha: str


class ReviewState(TypedDict, total=False):
    schema_version: str
    thread_id: str
    review_id: str
    repository: RepositoryContext
    commit_sha: str
    repo_path: str
    status: ReviewStatus
    current_stage: str
    attempts: dict[str, int]
    scanner_results: dict[str, object]
    security_results: dict[str, object]
    risk_assessment: dict[str, object]
    policy_decision: PolicyDecision
    approval: Approval
    merge_decision: dict[str, object]
    errors: list[dict[str, str]]
    audit_event_ids: list[str]
    updated_at: str
    latest_commit_sha: NotRequired[str]


NODE_NAMES = (
    "initialize_review",
    "check_still_current",
    "run_scanner",
    "run_security",
    "score_risk",
    "evaluate_policy",
    "request_human_approval",
    "validate_human_decision",
    "publish_decision",
    "finalize_review",
    "supersede_review",
    "handle_failure",
)
