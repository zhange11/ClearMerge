from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from backend.clearmerge.github.adapter import GitHubRepositoryAdapter
from backend.clearmerge.config import Settings
from backend.clearmerge.github.models import PullRequestEvent
from backend.clearmerge.services.reviews import ReviewService


class FakeGitHubClient:
    def __init__(self, repository: Path, commit_sha: str) -> None:
        self.repository = repository
        self.commit_sha = commit_sha

    def installation_token(self, installation_id: int) -> str:
        return "test-installation-token"

    def get_pull_request(self, token: str, owner: str, repository: str, number: int) -> dict:
        return {
            "head": {"sha": self.commit_sha, "repo": {"clone_url": str(self.repository)}},
            "base": {"repo": {"clone_url": str(self.repository)}},
        }

    def get_pull_request_files(self, token: str, owner: str, repository: str, number: int) -> list[dict]:
        return [{"filename": "reviewed.txt"}]

    def get_pull_request_diff(self, token: str, owner: str, repository: str, number: int) -> str:
        return "diff --git a/reviewed.txt b/reviewed.txt"


class RepositoryCheckoutTests(unittest.TestCase):
    def test_checks_out_exact_head_sha_and_returns_diff(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory:
            source = Path(source_directory)
            self._git(source, "init")
            self._git(source, "config", "user.email", "tests@example.com")
            self._git(source, "config", "user.name", "ClearMerge Tests")
            (source / "reviewed.txt").write_text("PR contents", encoding="utf-8")
            self._git(source, "add", "reviewed.txt")
            self._git(source, "commit", "-m", "reviewed commit")
            commit_sha = self._git(source, "rev-parse", "HEAD").stdout.strip()

            adapter = GitHubRepositoryAdapter(FakeGitHubClient(source, commit_sha))
            result = adapter.checkout_pull_request(42, "acme", "demo", 12, commit_sha)
            checkout = Path(result["repo_path"])
            try:
                self.assertEqual((checkout / "reviewed.txt").read_text(encoding="utf-8"), "PR contents")
                self.assertEqual(self._git(checkout, "rev-parse", "HEAD").stdout.strip(), commit_sha)
                self.assertEqual(result["diff"], "diff --git a/reviewed.txt b/reviewed.txt")
            finally:
                shutil.rmtree(checkout, ignore_errors=True)

    def test_review_graph_receives_checkout_path_and_diff(self) -> None:
        checkout = Path(tempfile.mkdtemp(prefix="clearmerge-test-checkout-"))
        captured: dict[str, object] = {}

        class FakeAdapter:
            def checkout_pull_request(self, *args):
                captured["checkout"] = checkout
                return {"repo_path": str(checkout), "diff": "exact PR diff"}

        class FakeGraph:
            def invoke(self, state, config):
                captured["state"] = dict(state)
                self.assertTrue(Path(state["repo_path"]).exists())
                self.assertEqual(state["diff_text"], "exact PR diff")
                return {**state, "status": "completed", "current_stage": "finalize_review"}

            def assertTrue(self, value):
                if not value:
                    raise AssertionError("checkout path was not available to the graph")

            def assertEqual(self, left, right):
                if left != right:
                    raise AssertionError(f"{left!r} != {right!r}")

        try:
            service = ReviewService(
                Settings.from_env({"REVIEW_WORKER_MODE": "inline"}),
                github=FakeAdapter(),
            )
            service._graph = FakeGraph()
            event = PullRequestEvent(
                delivery_id="delivery-checkout",
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
            record, created = service.create_from_event(event)
            self.assertTrue(created)
            self.assertEqual(record.state["repo_path"], "")
            self.assertFalse(checkout.exists())
            self.assertEqual(record.state["diff_text"], "exact PR diff")
        finally:
            shutil.rmtree(checkout, ignore_errors=True)

    @staticmethod
    def _git(directory: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=directory,
            capture_output=True,
            text=True,
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
