from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Sequence


class SecurityTool(StrEnum):
    SEMGREP = "semgrep"
    GITLEAKS = "gitleaks"


class SecurityStatus(StrEnum):
    COMPLETED = "completed"
    WARNING = "warning"
    FAILED = "failed"


@dataclass(frozen=True)
class SecurityToolSpec:
    name: SecurityTool | str
    command: tuple[str, ...]


@dataclass(frozen=True)
class SecurityFinding:
    id: str
    tool: str
    severity: str
    title: str
    description: str
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    evidence: str = "[REDACTED]"


@dataclass(frozen=True)
class SecurityToolResult:
    tool: str
    command: tuple[str, ...]
    status: SecurityStatus
    exit_code: int | None
    output: str
    error: str | None = None
    findings: tuple[SecurityFinding, ...] = ()


@dataclass(frozen=True)
class SecurityConfig:
    timeout_seconds: float = 300.0
    max_output_chars: int = 12_000
    tools: Sequence[SecurityToolSpec] | None = None


@dataclass
class SecurityReport:
    status: SecurityStatus
    summary: str
    tools: list[SecurityToolResult] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)
    warnings: list[dict[str, str]] = field(default_factory=list)
