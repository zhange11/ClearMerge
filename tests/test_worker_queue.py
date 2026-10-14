from __future__ import annotations

import unittest
from copy import deepcopy

from backend.clearmerge.services.queue import InMemoryReviewQueue, ReviewJob
from backend.clearmerge.services.worker import ReviewWorker
from backend.clearmerge.services.reviews import ReviewService
from backend.clearmerge.config import Settings
from backend.clearmerge.github.models import PullRequestEvent


class FakeReviewService:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.calls = 0
        self.failed = []

    def run_state(self, review_id, state):
        self.calls += 1
        if self.calls <= self.failures:
            raise RuntimeError("temporary failure")

    def mark_failed(self, review_id, code):
        self.failed.append((review_id, code))


class WorkerQueueTests(unittest.TestCase):
    def test_worker_processes_job(self) -> None:
        queue = InMemoryReviewQueue()
        service = FakeReviewService()
        queue.enqueue(ReviewJob("review-1", {"commit_sha": "abc"}))

        self.assertTrue(ReviewWorker(queue, service).process_once())
        self.assertEqual(service.calls, 1)
        self.assertFalse(ReviewWorker(queue, service).process_once())

    def test_worker_requeues_transient_failure(self) -> None:
        queue = InMemoryReviewQueue()
        service = FakeReviewService(failures=1)
        queue.enqueue(ReviewJob("review-1", {}))
        worker = ReviewWorker(queue, service, max_attempts=3)

        worker.process_once()
        self.assertEqual(len(queue), 1)
        worker.process_once()
        self.assertEqual(service.calls, 2)
        self.assertEqual(service.failed, [])

    def test_worker_marks_terminal_failure(self) -> None:
        queue = InMemoryReviewQueue()
        service = FakeReviewService(failures=5)
        queue.enqueue(ReviewJob("review-1", {}))
        worker = ReviewWorker(queue, service, max_attempts=2)

        worker.process_once()
        worker.process_once()

        self.assertEqual(service.failed, [("review-1", "worker_retry_limit")])
        self.assertEqual(len(queue), 0)

    def test_service_can_recover_from_serialized_job_state(self) -> None:
        queue = InMemoryReviewQueue()
        service = FakeReviewService()
        queue.enqueue(ReviewJob("review-1", {"thread_id": "review:review-1", "commit_sha": "abc"}))

        self.assertTrue(ReviewWorker(queue, service).process_once())

    def test_review_index_rehydrates_from_store(self) -> None:
        class Store:
            def __init__(self):
                self.records = []

            def load(self):
                return deepcopy(self.records)

            def save(self, record):
                self.records = [item for item in self.records if item.review_id != record.review_id]
                self.records.append(deepcopy(record))

            def close(self):
                pass

        store = Store()
        settings = Settings.from_env({"REVIEW_WORKER_MODE": "queue"})
        first = ReviewService(settings, queue=InMemoryReviewQueue(), store=store)
        event = PullRequestEvent(
            delivery_id="persistent-delivery",
            action="opened",
            owner="acme",
            repository="demo",
            installation_id=42,
            pull_request=12,
            commit_sha="abc123",
            title="Review",
            body="",
            sender_id=7,
            changed_files=1,
            additions=1,
            deletions=0,
            raw={},
        )
        record, _ = first.create_from_event(event)
        second = ReviewService(settings, queue=InMemoryReviewQueue(), store=store)
        self.assertEqual(second.get(record.review_id).state["commit_sha"], "abc123")
        self.assertEqual(second.list_records(repo="acme/demo")[0].review_id, record.review_id)


if __name__ == "__main__":
    unittest.main()