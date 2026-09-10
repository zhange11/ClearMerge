from __future__ import annotations

import subprocess
import time
from pathlib import Path

from ..llm.safety import sanitize_text_for_gemini
from .models import CheckResult, CheckSpec, CheckStatus


def redact(text: str) -> str:
    return sanitize_text_for_gemini(text)


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
        if _is_missing_python_module(spec, output):
            return CheckResult(
                name=spec.name,
                category=spec.category,
                command=spec.command,
                status=CheckStatus.SKIPPED,
                exit_code=completed.returncode,
                duration_ms=elapsed_ms(started),
                output=output[:max_output_chars],
                error=f"dependency tool is not installed: {spec.command[2]}",
            )
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


def _is_missing_python_module(spec: CheckSpec, output: str) -> bool:
    return (
        len(spec.command) >= 3
        and spec.command[1:2] == ("-m",)
        and f"No module named {spec.command[2]}" in output
    )
