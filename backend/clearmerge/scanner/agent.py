from __future__ import annotations

import json
from pathlib import Path

from ..llm.safety import sanitize_for_gemini
from .models import (
    CheckCategory,
    CheckResult,
    CheckSpec,
    CheckStatus,
    Finding,
    ScannerConfig,
    ScannerReport,
)
from .runner import run_check


class ScannerAgent:
    """Run deterministic repository checks and return LLM-ready evidence."""

    def __init__(self, repo_path: Path, config: ScannerConfig | None = None) -> None:
        self.repo_path = repo_path.resolve()
        self.config = config or ScannerConfig()

    def run(self) -> ScannerReport:
        specs = list(self.config.checks or discover_checks(self.repo_path))
        if not specs:
            return ScannerReport(
                status=CheckStatus.SKIPPED,
                summary="No supported test or dependency manifests were found.",
            )

        results = [
            run_check(
                self.repo_path,
                spec,
                self.config.timeout_seconds,
                self.config.max_output_chars,
            )
            for spec in specs
        ]
        findings = [finding_from_result(result) for result in results if result.status is not CheckStatus.PASSED]
        has_execution_failure = any(
            result.status in {CheckStatus.FAILED, CheckStatus.TIMED_OUT}
            for result in results
        )
        status = CheckStatus.FAILED if has_execution_failure else CheckStatus.PASSED
        return ScannerReport(
            status=status,
            summary=_summary(results),
            checks=results,
            findings=findings,
        )


def discover_checks(repo_path: Path) -> list[CheckSpec]:
    checks: list[CheckSpec] = []
    has_python = any((repo_path / name).exists() for name in ("pyproject.toml", "setup.py", "requirements.txt", " Pipfile".strip()))
    has_node = (repo_path / "package.json").exists()

    if has_python:
        checks.extend(
            (
                CheckSpec("python-tests", CheckCategory.TESTS, ("python", "-m", "pytest")),
                CheckSpec("python-dependencies", CheckCategory.DEPENDENCIES, ("python", "-m", "pip_audit", "--format", "json")),
            )
        )
    if has_node:
        checks.extend(
            (
                CheckSpec("node-tests", CheckCategory.TESTS, ("npm", "test", "--", "--runInBand")),
                CheckSpec("node-dependencies", CheckCategory.DEPENDENCIES, ("npm", "audit", "--json")),
            )
        )
    return checks


def finding_from_result(result: CheckResult) -> Finding:
    if result.status is CheckStatus.SKIPPED:
        severity = "low"
        title = f"{result.name} could not run"
        description = result.error or "The check executable was unavailable; this is a policy warning."
    elif result.status is CheckStatus.TIMED_OUT:
        severity = "high"
        title = f"{result.name} timed out"
        description = result.error or "The check exceeded its time limit."
    else:
        severity = "medium" if result.category is CheckCategory.TESTS else "high"
        title = f"{result.name} failed"
        description = result.error or "The check returned a non-zero exit code."

    return Finding(
        id=f"{result.category.value}:{result.name}",
        category=result.category,
        severity=severity,
        title=title,
        description=description,
        check_name=result.name,
        evidence=result.output,
    )


def _summary(results: list[CheckResult]) -> str:
    passed = sum(result.status is CheckStatus.PASSED for result in results)
    return f"{passed}/{len(results)} checks passed; {len(results) - passed} require attention."


def report_to_dict(report: ScannerReport) -> dict[str, object]:
    """Serialize the report for an API or prompt payload without raw subprocess objects."""
    payload = {
        "status": report.status.value,
        "summary": report.summary,
        "checks": [
            {
                "name": result.name,
                "category": result.category.value,
                "command": list(result.command),
                "status": result.status.value,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "output": result.output,
                "error": result.error,
            }
            for result in report.checks
        ],
        "findings": [
            {
                "id": finding.id,
                "category": finding.category.value,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description,
                "check_name": finding.check_name,
                "evidence": finding.evidence,
            }
            for finding in report.findings
        ],
    }
    return sanitize_for_gemini(payload)


def report_to_json(report: ScannerReport) -> str:
    return json.dumps(report_to_dict(report), indent=2)
