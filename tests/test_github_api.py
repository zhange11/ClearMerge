from __future__ import annotations

import hashlib
import hmac
import json
import unittest

from fastapi.testclient import TestClient

from backend.clearmerge.api.app import create_app
from backend.clearmerge.config import Settings


class GitHubApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "test-webhook-secret"
        settings = Settings.from_env({
            "GITHUB_WEBHOOK_SECRET": self.secret,
            "REVIEW_WORKER_MODE": "queue",
            "MAX_WEBHOOK_BODY_BYTES": "4096",
        })
        self.client = TestClient(create_app(settings=settings))

    def signed_headers(self, body: bytes, delivery: str = "delivery-1", event: str = "ping") -> dict[str, str]:
        digest = hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
        return {
            "x-hub-signature-256": f"sha256={digest}",
            "x-github-delivery": delivery,
            "x-github-event": event,
        }

    def payload(self) -> dict:
        return {
            "action": "opened",
            "installation": {"id": 42},
            "sender": {"id": 7},
            "repository": {"name": "demo", "owner": {"login": "acme"}},
            "pull_request": {
                "number": 12,
                "title": "Improve checks",
                "body": "Adds checks.",
                "head": {"sha": "abc123"},
                "changed_files": 2,
                "additions": 10,
                "deletions": 3,
            },
        }

    def test_health_and_ping(self) -> None:
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        body = b"{}"
        response = self.client.post("/webhooks/github", content=body, headers=self.signed_headers(body))
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.json()["ignored"])

    def test_invalid_signature_is_rejected_before_payload_processing(self) -> None:
        body = b"not-json"
        response = self.client.post(
            "/webhooks/github",
            content=body,
            headers={"x-hub-signature-256": "sha256=" + "0" * 64, "x-github-delivery": "d", "x-github-event": "pull_request"},
        )
        self.assertEqual(response.status_code, 401)

    def test_pull_request_is_accepted_and_duplicate_is_idempotent(self) -> None:
        body = json.dumps(self.payload()).encode()
        headers = self.signed_headers(body, delivery="delivery-pr", event="pull_request")
        first = self.client.post("/webhooks/github", content=body, headers=headers)
        second = self.client.post("/webhooks/github", content=body, headers=headers)

        self.assertEqual(first.status_code, 202)
        self.assertEqual(first.json()["status"], "accepted")
        self.assertEqual(second.json()["status"], "duplicate")
        review_id = first.json()["review_id"]
        review = self.client.get(f"/api/reviews/{review_id}")
        self.assertEqual(review.status_code, 200)
        self.assertEqual(review.json()["commit_sha"], "abc123")

    def test_body_limit_is_enforced(self) -> None:
        body = b"x" * 4097
        response = self.client.post("/webhooks/github", content=body, headers=self.signed_headers(body))
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()
