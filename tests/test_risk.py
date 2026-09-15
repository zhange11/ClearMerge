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

    def test_required_security_tool_failure_is_hard_block(self) -> None:
        state = self.state(
            repository_policy={"required_security_tools": ["gitleaks"]},
            security_results={
                "tools": [{"tool": "gitleaks", "status": "failed", "error": "unparseable output"}],
                "findings": [],
                "warnings": [],
            },
        )

        assessment = score_risk(state)

        self.assertIn("required_security_scan_missing", assessment["hard_blocks"])
        self.assertEqual(assessment["recommendation"], "block")

    def test_high_finding_can_be_hard_blocked_by_repository_policy(self) -> None:
        state = self.state(
            repository_policy={"block_high_findings": True},
            security_results={
                "findings": [{"id": "s1", "tool": "semgrep", "severity": "high", "title": "Risky sink"}],
                "warnings": [],
            },
        )

        assessment = score_risk(state)

        self.assertIn("s1", assessment["hard_blocks"])

    def test_suspicious_content_can_be_hard_blocked_by_policy(self) -> None:
        state = self.state(
            repository_policy={"block_suspicious_content": True},
            suspicious_diff_content=True,
        )

        assessment = score_risk(state)

        self.assertIn("suspicious_diff_content", assessment["hard_blocks"])

    def test_stale_and_mismatched_evidence_are_hard_blocks(self) -> None:
        stale = score_risk(self.state(latest_commit_sha="new", evidence_commit_sha="old"))

        self.assertIn("stale_review_evidence", stale["hard_blocks"])

    def test_invalid_model_without_safe_fallback_is_hard_block(self) -> None:
        state = self.state(deterministic_fallback_available=False)
        assessment = score_risk(state, lambda payload: {"score": "invalid"})

        self.assertIn("invalid_risk_assessment", assessment["hard_blocks"])
        self.assertEqual(assessment["recommendation"], "block")

    def test_invalid_model_enums_evidence_and_text_fall_back(self) -> None:
        state = self.state(
            security_results={
                "findings": [{"id": "s1", "tool": "semgrep", "severity": "medium", "title": "Finding"}],
                "warnings": [],
            }
        )

        invalid_candidates = (
            {"score": 20, "risk_level": "unknown", "recommendation": "allow"},
            {"score": 20, "risk_level": "low", "recommendation": "allow", "uncertainty": "unknown"},
            {"score": 20, "risk_level": "low", "recommendation": "allow", "confidence": 2},
            {"score": 20, "risk_level": "low", "recommendation": "allow", "factors": [{"impact": 1}]},
            {"score": 20, "risk_level": "low", "recommendation": "allow", "required_actions": ["x" * 501]},
        )

        for candidate in invalid_candidates:
            with self.subTest(candidate=candidate):
                assessment = score_risk(state, lambda payload, candidate=candidate: candidate)
                self.assertEqual(assessment["score"], 20)
                self.assertEqual(assessment["risk_level"], "low")

    def test_model_cannot_downgrade_medium_risk_to_allow(self) -> None:
        state = self.state(
            scanner_results={
                "checks": [{"name": "pytest", "category": "tests", "status": "failed"}],
                "findings": [],
                "warnings": [],
            }
        )

        assessment = score_risk(state, lambda payload: {"score": 1, "risk_level": "medium", "recommendation": "allow"})

        self.assertEqual(assessment["recommendation"], "require_approval")

    def test_low_risk_optional_tool_warning_requires_approval(self) -> None:
        state = self.state(
            scanner_results={
                "checks": [],
                "findings": [],
                "warnings": [{"code": "tool_warning", "message": "optional tool missing"}],
            }
        )

        assessment = score_risk(state)

        self.assertEqual(assessment["risk_level"], "low")
        self.assertEqual(assessment["recommendation"], "require_approval")

    def test_uncertainty_reduces_confidence_and_explains_why(self) -> None:
        state = self.state(
            security_results={
                "tools": [{"tool": "semgrep", "status": "failed", "error": "timeout"}],
                "findings": [],
                "warnings": [],
            }
        )

        assessment = score_risk(state)

        self.assertEqual(assessment["uncertainty"], "medium")
        self.assertEqual(assessment["confidence"], 0.7)
        self.assertTrue(assessment["uncertainty_reasons"])
        self.assertIn("Confidence is reduced", assessment["rationale"])

    def test_unavailable_security_tool_reduces_confidence(self) -> None:
        assessment = score_risk(self.state(
            security_results={
                "findings": [],
                "warnings": [{"tool": "semgrep", "code": "security_tool_unavailable", "message": "missing"}],
            }
        ))

        self.assertEqual(assessment["uncertainty"], "medium")
        self.assertEqual(assessment["confidence"], 0.7)
        self.assertIn("unavailable", assessment["rationale"])

    def test_stale_evidence_has_high_uncertainty(self) -> None:
        assessment = score_risk(self.state(latest_commit_sha="new"))

        self.assertEqual(assessment["uncertainty"], "high")
        self.assertEqual(assessment["confidence"], 0.4)

    def test_model_cannot_claim_more_certainty_than_evidence(self) -> None:
        state = self.state(
            security_results={
                "tools": [{"tool": "semgrep", "status": "failed", "error": "timeout"}],
                "findings": [],
                "warnings": [],
            }
        )

        assessment = score_risk(state, lambda payload: {"score": 0, "risk_level": "low", "recommendation": "allow", "confidence": 1.0})

        self.assertEqual(assessment["confidence"], 0.7)

    def test_dependency_and_tool_failure_weights_are_normalized(self) -> None:
        state = self.state(
            scanner_results={
                "checks": [{"name": "pip-audit", "category": "dependencies", "status": "failed"}],
                "findings": [],
                "warnings": [],
            },
            security_results={
                "tools": [{"tool": "semgrep", "status": "failed", "error": "timeout"}],
                "findings": [],
                "warnings": [],
            },
        )

        assessment = score_risk(state)

        self.assertEqual(assessment["score"], 35)
        self.assertEqual({factor["impact"] for factor in assessment["factors"]}, {20, 15})

    def test_failed_dependency_check_uses_dependency_weight(self) -> None:
        state = self.state(
            scanner_results={
                "checks": [{"name": "dependency-audit", "category": "dependency", "status": "failed"}],
                "findings": [],
                "warnings": [],
            }
        )

        assessment = score_risk(state)

        self.assertEqual(assessment["factors"][0]["code"], "failing_check")
        self.assertEqual(assessment["factors"][0]["impact"], 20)

    def test_sensitive_test_failure_uses_sensitive_test_weight(self) -> None:
        state = self.state(
            scanner_results={
                "checks": [],
                "findings": [{
                    "id": "test-auth",
                    "category": "tests",
                    "severity": "medium",
                    "title": "Authentication test failed",
                    "sensitive_area": "authentication",
                }],
                "warnings": [],
            }
        )

        assessment = score_risk(state)

        self.assertEqual(assessment["factors"][0]["impact"], 35)

    def test_change_scope_weights_are_normalized(self) -> None:
        state = self.state(
            change_scope={
                "sensitive_areas": ["authentication", "deployment"],
                "dependency_manifest_changed": True,
                "migration_changed": True,
                "lines_added": 600,
                "lines_deleted": 0,
                "behavior_change": True,
                "tests_added": False,
            }
        )

        assessment = score_risk(state)
        codes = {factor["code"] for factor in assessment["factors"]}

        self.assertEqual(assessment["score"], 60)
        self.assertEqual(codes, {
            "sensitive_area_change",
            "dependency_manifest_change",
            "migration_or_infrastructure_change",
            "large_change",
            "no_tests_added",
        })


if __name__ == "__main__":
    unittest.main()
