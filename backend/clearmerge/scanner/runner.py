from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

from .models import CheckResult, CheckSpec, CheckStatus

_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|password|secret|authorization)(\s*[:=]\s*)([\"']?)[^\s\"'&,]+"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+)\b"),
)


def redact(text: str) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 3:
            redacted = pattern.sub(r"\1\2\3[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def run_check(repo_path: Path, spec: CheckSpec, config_timeout: float, max_output_chars: int) -> CheckResult:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            spec.command,
            cwd=repo_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=config_timeout,
            check=False,
            shell=False,
        )
        output = redact((completed.stdout + "\n" + completed.stderr).strip())
        status = CheckStatus.PASSED if completed.returncode == 0 else CheckStatus.FAILED
        return CheckResult(
            name=spec.name,
            category=spec.category,
            command=spec.command,
            status=status,
            exit_code=completed.returncode,
            duration_ms=elapsed_ms(started),
            output=output[:max_output_chars],
        )
    except subprocess.TimeoutExpired as error:
        output = redact(_timeout_output(error))
        return CheckResult(
            name=spec.name,
            category=spec.category,
            command=spec.command,
            status=CheckStatus.TIMED_OUT,
            exit_code=None,
            duration_ms=elapsed_ms(started),
            output=output[:max_output_chars],
            error=f"check exceeded {config_timeout:g} seconds",
        )
    except FileNotFoundError as error:
        return CheckResult(
            name=spec.name,
            category=spec.category,
            command=spec.command,
            status=CheckStatus.SKIPPED,
            exit_code=None,
            duration_ms=elapsed_ms(started),
            output="",
            error=f"executable not found: {error.filename or spec.command[0]}",
        )
    except OSError as error:
        return CheckResult(
            name=spec.name,
            category=spec.category,
            command=spec.command,
            status=CheckStatus.FAILED,
            exit_code=None,
            duration_ms=elapsed_ms(started),
            output="",
            error=f"could not start check: {error}",
        )


def elapsed_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


def _timeout_output(error: subprocess.TimeoutExpired) -> str:
    parts = [value for value in (error.stdout, error.stderr) if value]
    return "\n".join(value.decode(errors="replace") if isinstance(value, bytes) else value for value in parts)
