from __future__ import annotations

import httpx
from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/reviews")


class ApprovalRequest(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    reviewer_id: int
    comment: str = ""
    commit_sha: str


class ManualReviewRequest(BaseModel):
    repo: str = Field(min_length=3, pattern=r"^[^/\s]+/[^/\s]+$")
    pull_request: int = Field(gt=0)


@router.get("")
async def list_reviews(
    request: Request,
    decision: str | None = Query(default=None, pattern="^(allow|require_approval|block)$"),
    repo: str | None = Query(default=None, min_length=3),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    service = request.app.state.review_service
    records = service.list_records(decision=decision, repo=repo)
    return {
        "items": [_summary(record.state) for record in records[offset:offset + limit]],
        "limit": limit,
        "offset": offset,
        "total": len(records),
    }


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_review(payload: ManualReviewRequest, request: Request):
    owner, repository = payload.repo.split("/", 1)
    installation_id = request.app.state.settings.github_installation_id
    if installation_id is None:
        raise HTTPException(status_code=503, detail="GITHUB_INSTALLATION_ID is not configured")
    try:
        record, created = request.app.state.review_service.create_manual(
            owner=owner,
            repository=repository,
            pull_request=payload.pull_request,
            installation_id=installation_id,
            authorized_reviewer_ids=list(request.app.state.settings.authorized_reviewer_ids),
        )
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except httpx.HTTPError as error:
        raise HTTPException(status_code=502, detail="GitHub API request failed") from error
    return {"created": created, **_public_state(record.state)}


@router.post("/{review_id}/retry", status_code=status.HTTP_202_ACCEPTED)
async def retry_review(review_id: str, request: Request):
    try:
        record = request.app.state.review_service.retry(review_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="review not found") from error
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    return _public_state(record.state)


@router.get("/{review_id}")
async def get_review(review_id: str, request: Request):
    record = request.app.state.review_service.get(review_id)
    if record is None:
        raise HTTPException(status_code=404, detail="review not found")
    return _public_state(record.state)


@router.post("/{review_id}/approval")
async def submit_approval(review_id: str, approval: ApprovalRequest, request: Request):
    record = request.app.state.review_service.get(review_id)
    if record is None:
        raise HTTPException(status_code=404, detail="review not found")
    if approval.commit_sha != record.state.get("commit_sha"):
        raise HTTPException(status_code=409, detail="approval does not match review commit")
    try:
        updated = request.app.state.review_service.approve(review_id, approval.model_dump())
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except KeyError as error:
        raise HTTPException(status_code=404, detail="review not found") from error
    return _public_state(updated.state)


def _public_state(state: dict) -> dict:
    return {
        "review_id": state.get("review_id"),
        "status": state.get("status"),
        "current_stage": state.get("current_stage"),
        "commit_sha": state.get("commit_sha"),
        "risk_assessment": state.get("risk_assessment"),
        "merge_decision": state.get("merge_decision"),
        "errors": state.get("errors", []),
        "pipeline_stages": state.get("pipeline_stages", []),
        "scanner_results": state.get("scanner_results", {}),
        "security_results": state.get("security_results", {}),
        "policy_decision": state.get("policy_decision"),
        "repository": state.get("repository"),
        "pr_title": state.get("pr_title"),
        "pr_body": state.get("pr_body"),
        "updated_at": state.get("updated_at"),
    }


def _summary(state: dict) -> dict:
    decision = state.get("merge_decision", {}).get("decision")
    return {
        "review_id": state.get("review_id"),
        "repository": state.get("repository"),
        "commit_sha": state.get("commit_sha"),
        "status": state.get("status"),
        "decision": decision,
        "risk_score": state.get("risk_assessment", {}).get("score"),
        "risk_level": state.get("risk_assessment", {}).get("risk_level"),
        "updated_at": state.get("updated_at"),
    }
