from __future__ import annotations

import unittest

from backend.clearmerge.workflow.policy import evaluate_policy
from backend.clearmerge.workflow.routes import (
    route_after_current_check,
    route_after_human_decision,
    route_after_policy,
)


class WorkflowRouteTests(unittest.TestCase):
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
        state = {"commit_sha": "abc", "approval": {"decision": "approve", "commit_sha": "abc"}}
        self.assertEqual(route_after_human_decision(state), "publish_decision")

    def test_policy_is_deterministic(self) -> None:
        self.assertEqual(evaluate_policy({"risk_level": "low"}, {}), "allow")
        self.assertEqual(evaluate_policy({"risk_level": "medium"}, {}), "require_approval")
        self.assertEqual(evaluate_policy({"risk_level": "low"}, {"findings": [{"severity": "critical"}]}), "block")


if __name__ == "__main__":
    unittest.main()
