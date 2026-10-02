from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PullRequestEvent:
    delivery_id: str
    action: str
    owner: str
    repository: str
    installation_id: int
    pull_request: int
    commit_sha: str
    title: str
    body: str
    sender_id: int | None
    changed_files: int
    additions: int
    deletions: int
    raw: dict[str, Any]

    @classmethod
    def from_payload(cls, delivery_id: str, payload: dict[str, Any]) -> "PullRequestEvent":
        repository = payload.get("repository") or {}
        pull_request = payload.get("pull_request") or {}
        head = pull_request.get("head") or {}
        owner_value = repository.get("owner") or {}
        owner = owner_value.get("login") or owner_value.get("name") if isinstance(owner_value, dict) else owner_value
        sender = payload.get("sender") or {}
        installation = payload.get("installation") or {}
        required = {
            "owner": owner,
            "repository": repository.get("name"),
            "pull_request": pull_request.get("number"),
            "commit_sha": head.get("sha"),
        }
        missing = [key for key, value in required.items() if not value]
        if missing:
            raise ValueError(f"missing pull request fields: {', '.join(missing)}")
        return cls(
            delivery_id=delivery_id,
            action=str(payload.get("action", "")),
            owner=str(owner),
            repository=str(repository["name"]),
            installation_id=int(installation.get("id", 0)),
            pull_request=int(pull_request["number"]),
            commit_sha=str(head["sha"]),
            title=str(pull_request.get("title") or ""),
            body=str(pull_request.get("body") or ""),
            sender_id=int(sender["id"]) if sender.get("id") is not None else None,
            changed_files=int(pull_request.get("changed_files") or 0),
            additions=int(pull_request.get("additions") or 0),
            deletions=int(pull_request.get("deletions") or 0),
            raw=payload,
        )
