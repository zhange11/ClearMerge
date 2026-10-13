from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .queue import ReviewJob, ReviewQueue


@dataclass
class ReviewWorker:
    queue: ReviewQueue
    review_service: Any
    max_attempts: int = 3

    def process_once(self, timeout_seconds: int = 0) -> bool:
        job = self.queue.dequeue(timeout_seconds)
        if job is None:
            return False
        try:
            self.review_service.run_state(job.review_id, job.state)
        except Exception:
            if job.attempt + 1 < self.max_attempts:
                self.queue.enqueue(ReviewJob(job.review_id, job.state, job.attempt + 1))
            else:
                self.review_service.mark_failed(job.review_id, "worker_retry_limit")
        return True

    def run_forever(self, timeout_seconds: int = 5) -> None:
        while True:
            self.process_once(timeout_seconds)