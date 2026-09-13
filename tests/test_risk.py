from __future__ import annotations

import unittest

from backend.clearmerge.workflow.risk import collect_risk_factors, score_risk


class RiskScorerTests(unittest.TestCase):
    def state(self, **updates):
        state = {
            "commit_sha": "abc123",
            "scanner_results": {
                "checks": [],
                "findings": [],
                "warnings": [],
            },
            "security_results": {
                "findings": [],
                "warnings": [],
            },
            "suspicious_diff_content": False,
        }
        state.update(updates)
        return state

    def test_all_security_findings_contribute_to_score(self) -> None:
        state = self.state(
            security_results={
                "findings": [
                    {"id": "s1", "tool": "semgrep", "severity": "high", "title": "Injection"},
                    {"id": "s2", "tool": "semgrep", "severity": "medium", "title": "Weak validation"},
                ],
                "warnings": [],
            }
        )

        assessment = score_risk(state)

        self.assertEqual(assessment["score"], 55)
        self.assertEqual(assessment["risk_level"], "medium")
        self.assertEqual(len(assessment["factors"]), 2)

    def test_confirmed_secret_is_hard_block(self) -> None:
        state = self.state(
            security_results={
                "findings": [{"id": "g1", "tool": "gitleaks", "severity": "high", "title": "API secret"}],
                "warnings": [],
            }
        )

        assessment = score_risk(state)

        self.assertEqual(assessment["recommendation"], "block")
        self.assertIn("g1", assessment["hard_blocks"])

    def test_failed_tests_reach_risk_scoring(self) -> None:
        state = self.state(
            scanner_results={
                "checks": [{"name": "pytest", "category": "tests", "status": "failed"}],
                "findings": [],
                "warnings": [],
            }
        )

        assessment = score_risk(state)

        self.assertEqual(assessment["score"], 25)
        self.assertEqual(assessment["risk_level"], "medium")

    def test_model_receives_sanitized_payload_and_invalid_output_falls_back(self) -> None:
        received = []
        state = self.state(
            security_results={
                "findings": [{"id": "s1", "tool": "semgrep", "severity": "medium", "description": "token=secret-value"}],
                "warnings": [],
            }
        )

        def invalid_model(payload):
            received.append(payload)
            return {"score": 999, "risk_level": "low", "recommendation": "allow"}

        assessment = score_risk(state, invalid_model)

        self.assertNotIn("secret-value", str(received[0]))
        self.assertEqual(assessment["score"], 20)
        self.assertEqual(assessment["risk_level"], "low")

    def test_valid_model_cannot_override_hard_block(self) -> None:
        state = self.state(
            security_results={
                "findings": [{"id": "g1", "tool": "gitleaks", "severity": "high", "title": "secret"}],
                "warnings": [],
            }
        )

        assessment = score_risk(state, lambda payload: {"score": 1, "risk_level": "low", "recommendation": "allow"})

        self.assertEqual(assessment["recommendation"], "block")


if __name__ == "__main__":
    unittest.main()
