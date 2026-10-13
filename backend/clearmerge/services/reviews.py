from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any
from uuid import uuid4

from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from ..config import Settings
from ..github.adapter import GitHubRepositoryAdapter
from ..github.models import PullRequestEvent
from ..workflow import build_review_graph, new_review_state
from .queue import ReviewJob, ReviewQueue


@dataclass
class ReviewRecord:
    review_id: str
    delivery_id: str
    thread_id: str
    state: dict[str, Any]


class ReviewService:
    """MVP review registry and graph dispatcher; replace storage with PostgreSQL/queue later."""

    def __init__(self, settings: Settings, github: GitHubRepositoryAdapter | None = None, queue: ReviewQueue | None = None) -> None:
        self.settings = settings
        self.github = github
        self.queue = queue
        self._lock = Lock()
        self._by_id: dict[str, ReviewRecord] = {}
        self._by_delivery: dict[str, str] = {}
        self._by_revision: dict[tuple[int, str, str, int], str] = {}
        self._checkpointer = MemorySaver()
        self._graph = build_review_graph(checkpointer=self._checkpointer)

    def create_from_event(self, event: PullRequestEvent) -> tuple[ReviewRecord, bool]:
        revision_key = (event.installation_id, event.owner, event.repository, event.pull_request)
        with self._lock:
            existing_delivery = self._by_delivery.get(event.delivery_id)
            if existing_delivery:
                return self._by_id[existing_delivery], False
            existing_revision = self._by_revision.get(revision_key)
            if existing_revision:
                existing = self._by_id[existing_revision]
                if existing.state.get("commit_sha") == event.commit_sha:
                    self._by_delivery[event.delivery_id] = existing.review_id
                    return existing, False
                existing.state["status"] = "superseded"
            review_id = str(uuid4())
            thread_id = f"review:{review_id}"
            state = new_review_state(
                thread_id=thread_id,
                review_id=review_id,
                repository={
                    "owner": event.owner,
                    "name": event.repository,
                    "installation_id": event.installation_id,
                    "pull_request": event.pull_request,
                },
                commit_sha=event.commit_sha,
                repo_path=str(Path.cwd()),
                pr_title=event.title,
                pr_body=event.body,
                change_scope={
                    "files_changed": event.changed_files,
                    "lines_added": event.additions,
                    "lines_deleted": event.deletions,
                },
            )
            if event.sender_id is not None:
                state["authorized_reviewer_ids"] = [event.sender_id]
            record = ReviewRecord(review_id, event.delivery_id, thread_id, state)
            self._by_id[review_id] = record
            self._by_delivery[event.delivery_id] = review_id
            self._by_revision[revision_key] = review_id
        if self.settings.review_worker_mode == "queue":
            if self.queue is None:
                raise RuntimeError("queue mode requires a review queue")
            self.queue.enqueue(ReviewJob(record.review_id, record.state))
        else:
            self._run(record)
            if self.github and record.state.get("merge_decision"):
                self.github.publish_decision(record.state)
        return record, True

    def get(self, review_id: str) -> ReviewRecord | None:
        return self._by_id.get(review_id)

    def approve(self, review_id: str, decision: dict[str, Any]) -> ReviewRecord:
        record = self._by_id.get(review_id)
        if record is None:
            raise KeyError(review_id)
        config = {"configurable": {"thread_id": record.thread_id}}
        result = self._graph.invoke(Command(resume=decision), config=config)
        record.state = dict(result)
        return record

    def run_state(self, review_id: str, state: dict[str, Any]) -> ReviewRecord:
        record = self._by_id.get(review_id)
        if record is None:
            record = ReviewRecord(
                review_id=review_id,
                delivery_id="worker-recovered",
                thread_id=str(state.get("thread_id", f"review:{review_id}")),
                state=state,
            )
            self._by_id[review_id] = record
        record.state = state
        self._run(record)
        if self.github and record.state.get("merge_decision"):
            self.github.publish_decision(record.state)
        return record

    def mark_failed(self, review_id: str, code: str) -> None:
        record = self._by_id.get(review_id)
        if record is not None:
            record.state.update({"status": "failed", "errors": [{"stage": "handle_failure", "code": code, "message": "Review worker retry limit reached.", "retryable": False}]})

    def _run(self, record: ReviewRecord) -> None:
        config = {"configurable": {"thread_id": record.thread_id}}
        result = self._graph.invoke(record.state, config=config)
        record.state = dict(result)
