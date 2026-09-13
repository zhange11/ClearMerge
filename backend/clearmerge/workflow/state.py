from __future__ import annotations

from datetime import datetime, timezone
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

StageName = Literal[
    "initialize_review",
    "inspect_pr_content",
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


class CheckpointRef(TypedDict):
    artifact_id: str
    kind: Literal["tool_output", "prompt", "model_response", "diff"]
    sha256: str


class ReviewError(TypedDict):
    stage: StageName
    code: str
    message: str
    retryable: bool


class MergeDecision(TypedDict, total=False):
    decision: PolicyDecision
    reason_codes: list[str]
    human_approval_required: bool
    github_check_conclusion: Literal["success", "failure", "neutral"]
    policy_version: str
    commit_sha: str


class ReviewState(TypedDict, total=False):
    schema_version: str
    thread_id: str
    review_id: str
    repository: RepositoryContext
    commit_sha: str
    repo_path: str
    pr_title: str
    pr_body: str
    diff_text: str
    suspicious_diff_content: bool
    suspicious_content_patterns: list[str]
    status: ReviewStatus
    current_stage: StageName
    attempts: dict[str, int]
    scanner_results: dict[str, object]
    security_results: dict[str, object]
    risk_assessment: dict[str, object]
    policy_decision: PolicyDecision
    approval: Approval
    authorized_reviewer_ids: list[int]
    merge_decision: MergeDecision
    errors: list[ReviewError]
    audit_event_ids: list[str]
    artifact_refs: list[CheckpointRef]
    updated_at: str
    latest_commit_sha: NotRequired[str]
    evidence_commit_sha: NotRequired[str]
    repository_policy: NotRequired[dict[str, object]]
    deterministic_fallback_available: NotRequired[bool]


STAGES: tuple[StageName, ...] = (
    "initialize_review",
    "inspect_pr_content",
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


LINEAR_STAGE_EDGES: tuple[tuple[StageName, StageName], ...] = (
    ("inspect_pr_content", "initialize_review"),
    ("initialize_review", "check_still_current"),
    ("run_scanner", "run_security"),
    ("run_security", "score_risk"),
    ("score_risk", "evaluate_policy"),
    ("publish_decision", "finalize_review"),
)


def new_review_state(
    *,
    thread_id: str,
    review_id: str,
    repository: RepositoryContext,
    commit_sha: str,
    repo_path: str,
    pr_title: str = "",
    pr_body: str = "",
    diff_text: str = "",
) -> ReviewState:
    """Create the minimum valid state for a new pull-request review."""
    return {
        "schema_version": "1.0",
        "thread_id": thread_id,
        "review_id": review_id,
        "repository": repository,
        "commit_sha": commit_sha,
        "latest_commit_sha": commit_sha,
        "repo_path": repo_path,
        "pr_title": pr_title,
        "pr_body": pr_body,
        "diff_text": diff_text,
        "suspicious_diff_content": False,
        "suspicious_content_patterns": [],
        "status": "queued",
        "current_stage": "initialize_review",
        "attempts": {},
        "errors": [],
        "audit_event_ids": [],
        "artifact_refs": [],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
