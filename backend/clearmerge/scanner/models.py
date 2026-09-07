from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Sequence


class CheckCategory(StrEnum):
    TESTS = "tests"
    DEPENDENCIES = "dependencies"
    CUSTOM = "custom"


class CheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class CheckSpec:
    name: str
    category: CheckCategory
    command: tuple[str, ...]


@dataclass(frozen=True)
class CheckResult:
    name: str
    category: CheckCategory
    command: tuple[str, ...]
    status: CheckStatus
    exit_code: int | None
    duration_ms: int
    output: str
    error: str | None = None


@dataclass(frozen=True)
class Finding:
    id: str
    category: CheckCategory
    severity: str
    title: str
    description: str
    check_name: str
    evidence: str


@dataclass(frozen=True)
class ScannerConfig:
    timeout_seconds: float = 300.0
    max_output_chars: int = 12_000
    checks: Sequence[CheckSpec] | None = None


@dataclass
class ScannerReport:
    status: CheckStatus
    summary: str
    checks: list[CheckResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.status is CheckStatus.PASSED
