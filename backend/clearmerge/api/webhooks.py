from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request

from ..github.models import PullRequestEvent
from ..github.signatures import InvalidGitHubSignature, verify_github_signature

router = APIRouter()
_SUPPORTED_ACTIONS = {"opened", "reopened", "synchronize", "ready_for_review"}


@router.post("/webhooks/github", status_code=202)
async def github_webhook(request: Request):
    settings = request.app.state.settings
    body = await request.body()
    if len(body) > settings.max_webhook_body_bytes:
        raise HTTPException(status_code=413, detail="request body too large")
    try:
        verify_github_signature(body, request.headers.get("x-hub-signature-256"), settings.github_webhook_secret)
    except InvalidGitHubSignature as error:
        raise HTTPException(status_code=401, detail="invalid webhook signature") from error
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=422, detail="invalid webhook JSON") from error

    event_name = request.headers.get("x-github-event", "")
    delivery_id = request.headers.get("x-github-delivery", "")
    if not delivery_id:
        raise HTTPException(status_code=422, detail="missing delivery id")
    if event_name == "ping":
        return {"status": "ok", "delivery_id": delivery_id, "ignored": True}
    if event_name != "pull_request":
        return {"status": "ignored", "delivery_id": delivery_id}

    try:
        event = PullRequestEvent.from_payload(delivery_id, payload)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail="invalid pull request event") from error
    if event.action not in _SUPPORTED_ACTIONS:
        return {"status": "ignored", "delivery_id": delivery_id, "action": event.action}

    record, created = request.app.state.review_service.create_from_event(event)
    return {
        "status": "accepted" if created else "duplicate",
        "delivery_id": delivery_id,
        "review_id": record.review_id,
        "commit_sha": event.commit_sha,
    }
