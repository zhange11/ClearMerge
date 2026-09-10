from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

_REDACTION_PREFIX = "[REDACTED sha256:"
_REDACTION_SUFFIX = "]"

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(api[_-]?key|token|password|secret|authorization)(\s*[:=]\s*)([\"']?)([^\s\"'&,]+)"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+|AIza[0-9A-Za-z_-]{20,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
)

_JSON_SECRET_PATTERN = re.compile(
    r'(?i)("?(?:api[_-]?key|token|password|secret|authorization)"?\s*:\s*")([^"]*)(")'
)


def sanitize_text_for_gemini(text: str) -> str:
    """Remove secret-shaped values and retain a non-reversible correlation hash."""
    sanitized = _JSON_SECRET_PATTERN.sub(
        lambda match: f'{match.group(1)}{_fingerprint(match.group(2))}{match.group(3)}',
        text,
    )
    for pattern in _SECRET_PATTERNS:
        sanitized = pattern.sub(_replace_match, sanitized)
    return sanitized


def sanitize_for_gemini(value: Any) -> Any:
    """Recursively sanitize a prompt payload before it is sent to Gemini.

    The returned value contains only JSON-compatible structures for mappings,
    sequences, and scalar values. Bytes and unknown objects are stringified and
    sanitized rather than passed through unchanged.
    """
    if isinstance(value, str):
        return sanitize_text_for_gemini(value)
    if isinstance(value, Mapping):
        return {str(key): sanitize_for_gemini(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [sanitize_for_gemini(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize_text_for_gemini(str(value))


def _replace_match(match: re.Match[str]) -> str:
    if match.lastindex and match.lastindex >= 4:
        return f"{match.group(1)}{match.group(2)}{match.group(3)}{_fingerprint(match.group(4))}"
    return _fingerprint(match.group(0))


def _fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{_REDACTION_PREFIX}{digest}{_REDACTION_SUFFIX}"
