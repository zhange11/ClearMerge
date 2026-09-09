from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from backend.clearmerge.security import SecurityAgent
from backend.clearmerge.security.models import SecurityConfig, SecurityStatus, SecurityToolSpec


class SecurityAgentTests(unittest.TestCase):
    def test_missing_tool_becomes_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = SecurityAgent(
                Path(directory),
                SecurityConfig(tools=(SecurityToolSpec("semgrep", ("missing-clearmerge-security-tool",)),)),
            ).run()

        self.assertEqual(report.status, SecurityStatus.WARNING)
        self.assertEqual(report.warnings[0]["severity"], "medium")

    def test_semgrep_findings_are_normalized(self) -> None:
        payload = json.dumps({"results": [{"check_id": "python.lang.security", "path": "app.py", "start": {"line": 4}, "extra": {"severity": "ERROR", "message": "Dangerous call"}}]})
        command = (sys.executable, "-c", f"print({payload!r})")
        with tempfile.TemporaryDirectory() as directory:
            report = SecurityAgent(Path(directory), SecurityConfig(tools=(SecurityToolSpec("semgrep", command),))).run()

        self.assertEqual(report.status, SecurityStatus.COMPLETED)
        self.assertEqual(report.findings[0].severity, "high")
        self.assertEqual(report.findings[0].file, "app.py")

    def test_gitleaks_secret_is_redacted(self) -> None:
        payload = json.dumps([{"RuleID": "generic-api-key", "Description": "API key", "File": ".env", "StartLine": 2, "Secret": "super-secret"}])
        command = (sys.executable, "-c", f"print({payload!r})")
        with tempfile.TemporaryDirectory() as directory:
            report = SecurityAgent(Path(directory), SecurityConfig(tools=(SecurityToolSpec("gitleaks", command),))).run()

        self.assertEqual(report.findings[0].evidence, "[REDACTED]")
        self.assertNotIn("super-secret", report_to_text(report))


def report_to_text(report) -> str:
    return str(report)


if __name__ == "__main__":
    unittest.main()
