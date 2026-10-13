from __future__ import annotations

import unittest

from backend.clearmerge.services.queue import InMemoryReviewQueue, ReviewJob
from backend.clearmerge.services.worker import ReviewWorker


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


if __name__ == "__main__":
    unittest.main()