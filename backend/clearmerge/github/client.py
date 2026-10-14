from __future__ import annotations

import time
from typing import Any

import httpx
import jwt

from ..config import Settings


class GitHubAppClient:
    """Small GitHub App client boundary; network methods are injectable in tests."""

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self.client = client or httpx.Client(base_url=settings.github_api_url, timeout=20.0)

    def app_jwt(self) -> str:
        self.settings.validate(require_github_app=True)
        now = int(time.time())
        return jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": self.settings.github_app_id},
            self.settings.private_key(),
            algorithm="RS256",
        )

    def installation_token(self, installation_id: int) -> str:
        response = self.client.post(
            f"/app/installations/{installation_id}/access_tokens",
            headers={"Authorization": "Bearer " + self.app_jwt(), "Accept": "application/vnd.github+json"},
        )
        response.raise_for_status()
        return str(response.json()["token"])

    def create_check_run(self, token: str, owner: str, repository: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.client.post(
            f"/repos/{owner}/{repository}/check-runs",
            headers=self._headers(token),
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    def get_pull_request(self, token: str, owner: str, repository: str, number: int) -> dict[str, Any]:
        response = self.client.get(f"/repos/{owner}/{repository}/pulls/{number}", headers=self._headers(token))
        response.raise_for_status()
        return response.json()

    def get_pull_request_files(self, token: str, owner: str, repository: str, number: int) -> list[dict[str, Any]]:
        response = self.client.get(f"/repos/{owner}/{repository}/pulls/{number}/files", headers=self._headers(token))
        response.raise_for_status()
        return response.json()

    def get_pull_request_diff(self, token: str, owner: str, repository: str, number: int) -> str:
        response = self.client.get(
            f"/repos/{owner}/{repository}/pulls/{number}",
            headers={**self._headers(token), "Accept": "application/vnd.github.diff"},
        )
        response.raise_for_status()
        return response.text

    def collaborator_permission(self, token: str, owner: str, repository: str, login: str) -> str:
        response = self.client.get(f"/repos/{owner}/{repository}/collaborators/{login}/permission", headers=self._headers(token))
        response.raise_for_status()
        return str(response.json().get("permission", "none"))

    def comment_on_pull_request(self, token: str, owner: str, repository: str, number: int, body: str) -> dict[str, Any]:
        response = self.client.post(
            f"/repos/{owner}/{repository}/issues/{number}/comments",
            headers=self._headers(token),
            json={"body": body},
        )
        response.raise_for_status()
        return response.json()

    def _headers(self, token: str) -> dict[str, str]:
        return {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"}
