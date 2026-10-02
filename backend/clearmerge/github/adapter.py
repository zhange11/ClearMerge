from __future__ import annotations

from typing import Any

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