from __future__ import annotations

import unittest
import tempfile
from unittest.mock import patch
from pathlib import Path

from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from backend.clearmerge.workflow import build_review_graph, new_review_state
from backend.clearmerge.security.models import SecurityReport, SecurityStatus


class ReviewGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = {"configurable": {"thread_id": "thread-1"}}
        self.initial_state = new_review_state(
            thread_id="thread-1",
            review_id="review-1",
            repository={"owner": "org", "name": "repo", "installation_id": 1, "pull_request": 42},
            commit_sha="abc123",
            repo_path="C:/sandbox/repo",
        )
        self.initial_state["authorized_reviewer_ids"] = [7]

    def _graph(self):
        return build_review_graph(
            nodes={
                "run_scanner": lambda state: {"status": "running", "scanner_results": {"status": "passed"}},
                "run_security": lambda state: {"status": "running", "security_results": {"findings": []}},
                "score_risk": lambda state: {"status": "running", "risk_assessment": {"risk_level": "medium"}},
            },
            checkpointer=MemorySaver(),
        )

    def test_medium_risk_interrupts_then_approval_allows_merge(self) -> None:
        graph = self._graph()

        paused = graph.invoke(self.initial_state, self.config)

        self.assertEqual(paused["status"], "waiting_for_approval")
        self.assertEqual(graph.get_state(self.config).tasks[0].interrupts[0].value["commit_sha"], "abc123")

        completed = graph.invoke(
            Command(
                resume={
                    "decision": "approve",
                    "reviewer_id": 7,
                    "comment": "Reviewed.",
                    "commit_sha": "abc123",
                }
            ),
            self.config,
        )

        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["merge_decision"]["decision"], "allow")

    def test_unauthorized_approval_blocks_merge(self) -> None:
        graph = self._graph()
        graph.invoke(self.initial_state, self.config)

        completed = graph.invoke(
            Command(
                resume={
                    "decision": "approve",
                    "reviewer_id": 99,
                    "comment": "Not authorized.",
                    "commit_sha": "abc123",
                }
            ),
            self.config,
        )

        self.assertEqual(completed["status"], "failed")

    def test_default_workflow_runs_scanner_and_routes_missing_tool_warning_to_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "pyproject.toml").write_text("[project]\nname = 'fixture'\nversion = '0.1.0'\n")
            state = dict(self.initial_state)
            state["repo_path"] = directory
            graph = build_review_graph(
                nodes={"run_security": lambda current: {"status": "running", "security_results": {"findings": []}}},
                checkpointer=MemorySaver(),
            )

            paused = graph.invoke(state, self.config)

        self.assertEqual(paused["status"], "waiting_for_approval")
        self.assertEqual(paused["scanner_results"]["status"], "passed")
        self.assertTrue(paused["scanner_results"]["warnings"])
        self.assertEqual(paused["risk_assessment"]["risk_level"], "medium")

    def test_default_security_node_warnings_reach_risk_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = dict(self.initial_state)
            state["repo_path"] = directory
            security_report = SecurityReport(
                status=SecurityStatus.WARNING,
                summary="1 security tool warning.",
                warnings=[{"tool": "gitleaks", "code": "security_tool_unavailable", "message": "missing", "severity": "medium"}],
            )
            with patch("backend.clearmerge.workflow.graph.SecurityAgent") as security_agent:
                security_agent.return_value.run.return_value = security_report
                graph = build_review_graph(
                    nodes={"run_scanner": lambda current: {"status": "running", "scanner_results": {"status": "passed"}}},
                    checkpointer=MemorySaver(),
                )
                paused = graph.invoke(state, self.config)

        self.assertEqual(paused["status"], "waiting_for_approval")
        self.assertEqual(paused["security_results"]["warnings"][0]["tool"], "gitleaks")
        self.assertEqual(paused["risk_assessment"]["risk_level"], "medium")


if __name__ == "__main__":
    unittest.main()