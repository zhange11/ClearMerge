from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

from .models import (
    SecurityConfig,
    SecurityFinding,
    SecurityReport,
    SecurityStatus,
    SecurityTool,
    SecurityToolResult,
    SecurityToolSpec,
)
from ..scanner.runner import redact


class SecurityAgent:
    """Run Semgrep and Gitleaks, returning normalized security evidence."""

    def __init__(self, repo_path: Path, config: SecurityConfig | None = None) -> None:
        self.repo_path = repo_path.resolve()
        self.config = config or SecurityConfig()

    def run(self) -> SecurityReport:
        specs = list(self.config.tools or default_tools())
        results: list[SecurityToolResult] = []
        findings: list[SecurityFinding] = []
        warnings: list[dict[str, str]] = []

        for spec in specs:
            result = run_security_tool(self.repo_path, spec, self.config)
            results.append(result)
            findings.extend(result.findings)
            if result.status is SecurityStatus.WARNING:
                warnings.append({
                    "tool": result.tool,
                    "code": "security_tool_unavailable",
                    "message": result.error or f"{result.tool} was unavailable.",
                    "severity": "medium",
                })

        status = SecurityStatus.WARNING if warnings else SecurityStatus.COMPLETED
        if any(result.status is SecurityStatus.FAILED for result in results):
            status = SecurityStatus.FAILED
        return SecurityReport(
            status=status,
            summary=f"{len(findings)} security findings; {len(warnings)} tool warnings.",
            tools=results,
            findings=findings,
            warnings=warnings,
        )


def default_tools() -> tuple[SecurityToolSpec, ...]:
    return (
        SecurityToolSpec(SecurityTool.SEMGREP, ("semgrep", "scan", "--config", "auto", "--json", "--quiet", ".")),
        SecurityToolSpec(SecurityTool.GITLEAKS, ("gitleaks", "detect", "--source", ".", "--report-format", "json", "--report-path", "-", "--no-banner")),
    )


def run_security_tool(repo_path: Path, spec: SecurityToolSpec, config: SecurityConfig) -> SecurityToolResult:
    started = time.monotonic()
    safe_command = tuple(redact(argument) for argument in spec.command)
    try:
        completed = subprocess.run(
            spec.command,
            cwd=repo_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=config.timeout_seconds,
            check=False,
            shell=False,
        )
    except FileNotFoundError as error:
        return SecurityToolResult(
            tool=str(spec.name), command=safe_command, status=SecurityStatus.WARNING,
            exit_code=None, output="", error=f"executable not found: {error.filename or spec.command[0]}",
        )
    except subprocess.TimeoutExpired as error:
        return SecurityToolResult(
            tool=str(spec.name), command=safe_command, status=SecurityStatus.FAILED,
            exit_code=None, output=redact(_timeout_output(error))[:config.max_output_chars],
            error=f"{spec.name} exceeded {config.timeout_seconds:g} seconds",
        )
    except OSError as error:
        return SecurityToolResult(
            tool=str(spec.name), command=safe_command, status=SecurityStatus.FAILED,
            exit_code=None, output="", error=f"could not start security tool: {error}",
        )

    output = redact((completed.stdout + "\n" + completed.stderr).strip())
    findings = parse_findings(str(spec.name), output)
    # Semgrep and Gitleaks use non-zero exits to indicate findings.
    if completed.returncode not in (0, 1):
        return SecurityToolResult(
            tool=str(spec.name), command=safe_command, status=SecurityStatus.FAILED,
            exit_code=completed.returncode, output=output[:config.max_output_chars],
            error=f"{spec.name} exited with code {completed.returncode}", findings=tuple(findings),
        )
    return SecurityToolResult(
        tool=str(spec.name), command=safe_command, status=SecurityStatus.COMPLETED,
        exit_code=completed.returncode, output=output[:config.max_output_chars], findings=tuple(findings),
    )


def parse_findings(tool: str, output: str) -> list[SecurityFinding]:
    try:
        payload = json.loads(output) if output else []
    except json.JSONDecodeError:
        return []
    if tool == SecurityTool.SEMGREP:
        return [_semgrep_finding(item, index) for index, item in enumerate(payload.get("results", []))]
    if tool == SecurityTool.GITLEAKS:
        return [_gitleaks_finding(item, index) for index, item in enumerate(payload if isinstance(payload, list) else [])]
    return []


def _semgrep_finding(item: dict[str, Any], index: int) -> SecurityFinding:
    extra = item.get("extra", {})
    severity = str(extra.get("severity", "WARNING")).lower()
    return SecurityFinding(
        id=f"semgrep:{index}:{item.get('check_id', 'finding')}", tool="semgrep", severity=_severity(severity),
        title=str(item.get("check_id", "Semgrep finding")), description=str(extra.get("message", "Semgrep reported a finding.")),
        file=item.get("path"), line_start=item.get("start", {}).get("line"), line_end=item.get("end", {}).get("line"),
        evidence="[REDACTED]",
    )


def _gitleaks_finding(item: dict[str, Any], index: int) -> SecurityFinding:
    return SecurityFinding(
        id=f"gitleaks:{index}:{item.get('RuleID', 'secret')}", tool="gitleaks", severity="high",
        title=str(item.get("RuleID", "Potential secret")), description=str(item.get("Description", "Gitleaks detected a potential secret.")),
        file=item.get("File"), line_start=item.get("StartLine"), line_end=item.get("EndLine"), evidence="[REDACTED]",
    )


def _severity(value: str) -> str:
    return {"error": "high", "warning": "medium", "info": "low"}.get(value, "medium")


def _timeout_output(error: subprocess.TimeoutExpired) -> str:
    values = [value for value in (error.stdout, error.stderr) if value]
    return "\n".join(value.decode(errors="replace") if isinstance(value, bytes) else value for value in values)


def report_to_dict(report: SecurityReport) -> dict[str, object]:
    return {
        "status": report.status.value,
        "summary": report.summary,
        "warnings": report.warnings,
        "tools": [
            {"tool": item.tool, "command": list(item.command), "status": item.status.value, "exit_code": item.exit_code, "output": item.output, "error": item.error}
            for item in report.tools
        ],
        "findings": [
            {"id": item.id, "tool": item.tool, "severity": item.severity, "title": item.title, "description": item.description, "file": item.file, "line_start": item.line_start, "line_end": item.line_end, "evidence": item.evidence}
            for item in report.findings
        ],
    }
