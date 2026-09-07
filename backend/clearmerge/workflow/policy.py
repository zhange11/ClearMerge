from __future__ import annotations

from typing import Literal

from .state import PolicyDecision


def evaluate_policy(risk_assessment: dict[str, object], security_results: dict[str, object]) -> PolicyDecision:
    """Apply merge policy deterministically; the LLM never chooses enforcement."""
    risk_level = risk_assessment.get("risk_level")
    findings = security_results.get("findings", [])
    has_critical = any(isinstance(item, dict) and item.get("severity") == "critical" for item in findings)

    if risk_level in {"critical", "high"} or has_critical:
        return "block"
    if risk_level == "medium":
        return "require_approval"
    if risk_level == "low":
        return "allow"
    raise ValueError("risk assessment has no supported risk_level")
