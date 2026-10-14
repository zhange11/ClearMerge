from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
from typing import Any
from pathlib import Path

from .client import GitHubAppClient


class GitHubRepositoryAdapter:
    """Repository operations used by review services, backed by a GitHub App."""

    def __init__(self, client: GitHubAppClient) -> None:
        self.client = client

    def pull_request_context(self, installation_id: int, owner: str, repository: str, number: int) -> dict[str, Any]:
        token = self.client.installation_token(installation_id)
        pull_request = self.client.get_pull_request(token, owner, repository, number)
        files = self.client.get_pull_request_files(token, owner, repository, number)
        return {
            "pull_request": pull_request,
            "files": files,
            "diff": self.client.get_pull_request_diff(token, owner, repository, number),
        }

    def checkout_pull_request(
        self,
        installation_id: int,
        owner: str,
        repository: str,
        number: int,
        commit_sha: str,
    ) -> dict[str, Any]:
        """Fetch PR metadata and check out its exact head into an isolated temp directory."""
        token = self.client.installation_token(installation_id)
        pull_request = self.client.get_pull_request(token, owner, repository, number)
        files = self.client.get_pull_request_files(token, owner, repository, number)
        diff = self.client.get_pull_request_diff(token, owner, repository, number)
        checkout_dir = Path(tempfile.mkdtemp(prefix="clearmerge-review-"))
        clone_url = _clone_url(pull_request, owner, repository)
        auth = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
        env = {
            **os.environ,
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {auth}",
            "GIT_TERMINAL_PROMPT": "0",
        }
        try:
            _run_git(["clone", "--quiet", "--no-checkout", clone_url, str(checkout_dir)], env=env)
            _run_git(["-C", str(checkout_dir), "checkout", "--quiet", "--detach", commit_sha], env=env)
        except Exception:
            shutil.rmtree(checkout_dir, ignore_errors=True)
            raise
        return {
            "repo_path": str(checkout_dir),
            "pull_request": pull_request,
            "files": files,
            "diff": diff,
        }

    def publish_decision(self, state: dict[str, Any]) -> None:
        repository = state["repository"]
        owner = repository["owner"]
        name = repository["name"]
        installation_id = repository["installation_id"]
        number = repository["pull_request"]
        decision = state.get("merge_decision", {})
        token = self.client.installation_token(installation_id)
        conclusion = decision.get("github_check_conclusion", "failure")
        self.client.create_check_run(token, owner, name, {
            "name": "ClearMerge",
            "head_sha": state["commit_sha"],
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": f"ClearMerge: {decision.get('decision', 'block')}",
                "summary": state.get("risk_assessment", {}).get("rationale", "Review completed."),
            },
        })
        self.client.comment_on_pull_request(
            token,
            owner,
            name,
            number,
            f"ClearMerge decision: **{decision.get('decision', 'block')}**\n\n{state.get('risk_assessment', {}).get('rationale', '')}",
        )


def _clone_url(pull_request: dict[str, Any], owner: str, repository: str) -> str:
    head_repo = (pull_request.get("head") or {}).get("repo") or {}
    base_repo = (pull_request.get("base") or {}).get("repo") or {}
    return str(head_repo.get("clone_url") or base_repo.get("clone_url") or f"https://github.com/{owner}/{repository}.git")


def _run_git(command: list[str], *, env: dict[str, str]) -> None:
    completed = subprocess.run(
        ["git", *command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"git {' '.join(command[:2])} failed: {detail or 'unknown error'}")