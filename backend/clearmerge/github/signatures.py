from __future__ import annotations

import hashlib
import hmac


class InvalidGitHubSignature(ValueError):
    """Raised when a GitHub webhook signature is absent or invalid."""


def verify_github_signature(body: bytes, signature_header: str | None, secret: str | None) -> None:
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        raise InvalidGitHubSignature("invalid webhook signature")
    supplied = signature_header.removeprefix("sha256=")
    if len(supplied) != 64 or any(character not in "0123456789abcdefABCDEF" for character in supplied):
        raise InvalidGitHubSignature("invalid webhook signature")
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied):
        raise InvalidGitHubSignature("invalid webhook signature")
