from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/reviews")


class ApprovalRequest(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    reviewer_id: int
    comment: str = ""
    commit_sha: str


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
    }
