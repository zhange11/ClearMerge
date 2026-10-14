from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from ..config import Settings
from ..github.adapter import GitHubRepositoryAdapter
from ..github.models import PullRequestEvent
from ..workflow import build_review_graph, new_review_state
from ..workflow.state import STAGES
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

    def create_from_event(
        self,
        event: PullRequestEvent,
        *,
        diff_text: str = "",
        authorized_reviewer_ids: list[int] | None = None,
    ) -> tuple[ReviewRecord, bool]:
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
                diff_text=diff_text,
                change_scope={
                    "files_changed": event.changed_files,
                    "lines_added": event.additions,
                    "lines_deleted": event.deletions,
                },
            )
            state["authorized_reviewer_ids"] = authorized_reviewer_ids or (
                [event.sender_id] if event.sender_id is not None else []
            )
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

    def create_manual(
        self,
        *,
        owner: str,
        repository: str,
        pull_request: int,
        installation_id: int,
        authorized_reviewer_ids: list[int] | None = None,
    ) -> tuple[ReviewRecord, bool]:
        if self.github is None:
            raise RuntimeError("GitHub integration is not configured")
        context = self.github.pull_request_context(installation_id, owner, repository, pull_request)
        pull_request_data = context["pull_request"]
        head = pull_request_data.get("head") or {}
        payload = {
            "action": "synchronize",
            "installation": {"id": installation_id},
            "repository": {"name": repository, "owner": {"login": owner}},
            "pull_request": {
                **pull_request_data,
                "number": pull_request,
                "head": head,
                "title": pull_request_data.get("title", ""),
                "body": pull_request_data.get("body") or "",
                "changed_files": len(context.get("files", [])),
            },
        }
        event = PullRequestEvent.from_payload(f"manual:{owner}/{repository}:{pull_request}:{head.get('sha', '')}", payload)
        return self.create_from_event(
            event,
            diff_text=context.get("diff", ""),
            authorized_reviewer_ids=authorized_reviewer_ids,
        )

    def get(self, review_id: str) -> ReviewRecord | None:
        return self._by_id.get(review_id)

    def approve(self, review_id: str, decision: dict[str, Any]) -> ReviewRecord:
        record = self._by_id.get(review_id)
        if record is None:
            raise KeyError(review_id)
        if record.state.get("policy_decision") != "require_approval":
            raise ValueError("review does not require approval")
        config = {"configurable": {"thread_id": record.thread_id}}
        result = self._graph.invoke(Command(resume=decision), config=config)
        record.state = dict(result)
        _update_pipeline_stages(record.state)
        return record

    def retry(self, review_id: str) -> ReviewRecord:
        record = self._by_id.get(review_id)
        if record is None:
            raise KeyError(review_id)
        if record.state.get("status") != "failed":
            raise ValueError("only failed reviews can be retried")
        state = dict(record.state)
        state.update({
            "status": "queued",
            "current_stage": "initialize_review",
            "errors": [],
            "merge_decision": {},
            "approval": {},
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        record.state = state
        if self.settings.review_worker_mode == "queue":
            if self.queue is None:
                raise RuntimeError("queue mode requires a review queue")
            self.queue.enqueue(ReviewJob(record.review_id, state))
        else:
            self._run(record)
            if self.github and record.state.get("merge_decision"):
                self.github.publish_decision(record.state)
        return record

    def list_records(self, *, decision: str | None = None, repo: str | None = None) -> list[ReviewRecord]:
        with self._lock:
            records = list(self._by_id.values())
        if decision:
            records = [record for record in records if record.state.get("merge_decision", {}).get("decision") == decision]
        if repo:
            records = [
                record for record in records
                if _repository_name(record.state) == repo
            ]
        return sorted(records, key=lambda record: record.state.get("updated_at", ""), reverse=True)

    def stats(self) -> dict[str, Any]:
        records = self.list_records()
        by_decision = {"allow": 0, "require_approval": 0, "block": 0, "pending": 0}
        scores: list[int] = []
        over_time: dict[str, int] = {}
        for record in records:
            decision = record.state.get("merge_decision", {}).get("decision")
            by_decision[decision if decision in {"allow", "require_approval", "block"} else "pending"] += 1
            score = record.state.get("risk_assessment", {}).get("score")
            if isinstance(score, (int, float)):
                scores.append(int(score))
            updated_at = str(record.state.get("updated_at", ""))
            if len(updated_at) >= 10:
                over_time[updated_at[:10]] = over_time.get(updated_at[:10], 0) + 1
        return {
            "total_reviews": len(records),
            "by_decision": by_decision,
            "average_risk_score": round(sum(scores) / len(scores), 2) if scores else None,
            "reviews_over_time": [
                {"date": date, "count": count} for date, count in sorted(over_time.items())
            ],
        }

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
        record.state["updated_at"] = datetime.now(timezone.utc).isoformat()
        _update_pipeline_stages(record.state)


def _repository_name(state: dict[str, Any]) -> str:
    repository = state.get("repository", {})
    owner = repository.get("owner")
    name = repository.get("name")
    return f"{owner}/{name}" if owner and name else ""


def _update_pipeline_stages(state: dict[str, Any]) -> None:
    current = state.get("current_stage")
    current_index = STAGES.index(current) if current in STAGES else -1
    terminal = state.get("status") in {"completed", "blocked", "failed", "superseded"}
    stages = []
    for index, stage in enumerate(STAGES):
        if index < current_index or (index == current_index and terminal):
            stage_status = "completed"
        elif index == current_index:
            stage_status = "running"
        else:
            stage_status = "pending"
        stages.append({"name": stage, "status": stage_status})
    state["pipeline_stages"] = stages
