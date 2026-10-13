from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Any, Protocol


@dataclass(frozen=True)
class ReviewJob:
    review_id: str
    state: dict[str, Any]
    attempt: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"review_id": self.review_id, "state": self.state, "attempt": self.attempt}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ReviewJob":
        return cls(str(payload["review_id"]), dict(payload["state"]), int(payload.get("attempt", 0)))


class ReviewQueue(Protocol):
    def enqueue(self, job: ReviewJob) -> None: ...
    def dequeue(self, timeout_seconds: int = 0) -> ReviewJob | None: ...


class InMemoryReviewQueue:
    def __init__(self) -> None:
        self._jobs: deque[ReviewJob] = deque()
        self._lock = Lock()

    def enqueue(self, job: ReviewJob) -> None:
        with self._lock:
            self._jobs.append(job)

    def dequeue(self, timeout_seconds: int = 0) -> ReviewJob | None:
        with self._lock:
            return self._jobs.popleft() if self._jobs else None

    def __len__(self) -> int:
        return len(self._jobs)


class RedisReviewQueue:
    """Redis list-backed queue. BLPOP removes a job only when a worker claims it."""

    def __init__(self, redis_url: str, queue_name: str = "clearmerge:reviews") -> None:
        from redis import Redis

        self.client = Redis.from_url(redis_url, decode_responses=True)
        self.queue_name = queue_name

    def enqueue(self, job: ReviewJob) -> None:
        self.client.rpush(self.queue_name, json.dumps(job.to_dict(), separators=(",", ":")))

    def dequeue(self, timeout_seconds: int = 0) -> ReviewJob | None:
        result = self.client.blpop(self.queue_name, timeout=timeout_seconds)
        if result is None:
            return None
        _, payload = result
        return ReviewJob.from_dict(json.loads(payload))