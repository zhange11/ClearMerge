from __future__ import annotations

import unittest

from backend.clearmerge.workflow.policy import evaluate_policy
from backend.clearmerge.workflow.routes import (
    route_after_current_check,
    route_after_human_decision,
    route_after_policy,
)
from backend.clearmerge.workflow.state import STAGES, new_review_state


class WorkflowRouteTests(unittest.TestCase):
    def test_new_review_state_has_execution_identity(self) -> None:
        state = new_review_state(
            thread_id="thread-1",
            review_id="review-1",
            repository={"owner": "org", "name": "repo", "installation_id": 1, "pull_request": 42},
            commit_sha="abc",
            repo_path="C:/sandbox/repo",
        )

        self.assertEqual(state["status"], "queued")
        self.assertEqual(state["current_stage"], "initialize_review")
        self.assertEqual(state["latest_commit_sha"], "abc")
        self.assertEqual(len(STAGES), 12)

    def test_current_commit_runs_scanner(self) -> None:
        state = {"commit_sha": "abc", "latest_commit_sha": "abc"}
        self.assertEqual(route_after_current_check(state), "run_scanner")

    def test_stale_commit_is_superseded(self) -> None:
        state = {"commit_sha": "abc", "latest_commit_sha": "def"}
        self.assertEqual(route_after_current_check(state), "supersede_review")

    def test_policy_routes_to_approval(self) -> None:
        state = {"policy_decision": "require_approval"}
        self.assertEqual(route_after_policy(state), "request_human_approval")

    def test_human_approval_routes_to_publish(self) -> None:
        state = {
            "commit_sha": "abc",
            "authorized_reviewer_ids": [987],
            "approval": {"decision": "approve", "reviewer_id": 987, "commit_sha": "abc"},
        }
        self.assertEqual(route_after_human_decision(state), "publish_decision")

    def test_unauthorized_human_decision_fails(self) -> None:
        state = {
            "commit_sha": "abc",
            "authorized_reviewer_ids": [987],
            "approval": {"decision": "approve", "reviewer_id": 123, "commit_sha": "abc"},
        }
        self.assertEqual(route_after_human_decision(state), "handle_failure")

    def test_policy_is_deterministic(self) -> None:
        self.assertEqual(evaluate_policy({"risk_level": "low"}, {}), "allow")
        self.assertEqual(evaluate_policy({"risk_level": "medium"}, {}), "require_approval")
        self.assertEqual(evaluate_policy({"risk_level": "low"}, {"findings": [{"severity": "critical"}]}), "block")


if __name__ == "__main__":
    unittest.main()
