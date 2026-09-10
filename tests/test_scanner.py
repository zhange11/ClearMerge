from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from backend.clearmerge.scanner.agent import ScannerAgent, report_to_dict
from backend.clearmerge.scanner.models import CheckCategory, CheckResult, CheckSpec, CheckStatus, Finding, ScannerConfig, ScannerReport
from backend.clearmerge.scanner.runner import redact


class ScannerAgentTests(unittest.TestCase):
    def test_runs_explicit_checks_and_serializes_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = ScannerAgent(
                Path(directory),
                ScannerConfig(
                    checks=(
                        CheckSpec("passing-test", CheckCategory.TESTS, (sys.executable, "-c", "print('ok')")),
                        CheckSpec("passing-dependency", CheckCategory.DEPENDENCIES, (sys.executable, "-c", "print('clean')")),
                    )
                ),
            ).run()

        self.assertEqual(report.status, CheckStatus.PASSED)
        self.assertEqual(report.summary, "2/2 checks passed; 0 require attention.")
        self.assertEqual(report_to_dict(report)["checks"][0]["status"], "passed")

    def test_failed_check_becomes_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = ScannerAgent(
                Path(directory),
                ScannerConfig(
                    checks=(CheckSpec("tests", CheckCategory.TESTS, (sys.executable, "-c", "raise SystemExit(2)")),)
                ),
            ).run()

        self.assertEqual(report.status, CheckStatus.FAILED)
        self.assertEqual(report.findings[0].severity, "medium")
        self.assertEqual(report.findings[0].id, "tests:tests")

    def test_missing_executable_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = ScannerAgent(
                Path(directory),
                ScannerConfig(
                    checks=(CheckSpec("dependency-tool", CheckCategory.DEPENDENCIES, ("not-installed-clearmerge-tool",)),)
                ),
            ).run()

        self.assertEqual(report.checks[0].status, CheckStatus.SKIPPED)
        self.assertEqual(report.status, CheckStatus.PASSED)
        self.assertEqual(report.findings[0].severity, "low")

    def test_timeout_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = ScannerAgent(
                Path(directory),
                ScannerConfig(
                    timeout_seconds=0.01,
                    checks=(CheckSpec("slow-test", CheckCategory.TESTS, (sys.executable, "-c", "import time; time.sleep(1)")),),
                ),
            ).run()

        self.assertEqual(report.checks[0].status, CheckStatus.TIMED_OUT)
        self.assertEqual(report.findings[0].severity, "high")

    def test_output_redacts_credentials(self) -> None:
        output = redact("GEMINI_API_KEY=super-secret-value ghp_123456789")
        self.assertNotIn("super-secret-value", output)
        self.assertNotIn("ghp_123456789", output)
        self.assertIn("[REDACTED sha256:", output)

    def test_missing_python_module_is_a_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = ScannerAgent(
                Path(directory),
                ScannerConfig(
                    checks=(CheckSpec("missing-module", CheckCategory.DEPENDENCIES, (sys.executable, "-m", "not_installed_clearmerge_tool")),)
                ),
            ).run()

        self.assertEqual(report.status, CheckStatus.PASSED)
        self.assertEqual(report.checks[0].status, CheckStatus.SKIPPED)
        self.assertEqual(report.findings[0].severity, "low")

    def test_serialized_report_redacts_and_hashes_all_secret_shaped_fields(self) -> None:
        secret = "ghp_scanner_secret_123"
        report = ScannerReport(
            status=CheckStatus.FAILED,
            summary="check failed",
            checks=[
                CheckResult(
                    name="tests",
                    category=CheckCategory.TESTS,
                    command=("tool", f"token={secret}"),
                    status=CheckStatus.FAILED,
                    exit_code=1,
                    duration_ms=3,
                    output=f'{{"Secret": "{secret}"}}',
                    error=f"password: {secret}",
                )
            ],
            findings=[
                Finding(
                    id="tests:tests",
                    category=CheckCategory.TESTS,
                    severity="medium",
                    title="Failure",
                    description=f"Authorization: {secret}",
                    check_name="tests",
                    evidence=secret,
                )
            ],
        )

        serialized = report_to_dict(report)
        serialized_text = str(serialized)

        self.assertNotIn(secret, serialized_text)
        self.assertGreaterEqual(serialized_text.count("[REDACTED sha256:"), 5)
        command_fingerprint = serialized["checks"][0]["command"][1].split("[REDACTED ", 1)[1]
        self.assertIn(command_fingerprint, serialized["findings"][0]["evidence"])


if __name__ == "__main__":
    unittest.main()
