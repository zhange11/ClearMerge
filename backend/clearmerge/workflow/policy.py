from __future__ import annotations

from typing import Literal

from .state import PolicyDecision


def evaluate_policy(
    risk_assessment: dict[str, object],
    security_results: dict[str, object],
    scanner_results: dict[str, object] | None = None,
) -> PolicyDecision:
    """Apply merge policy deterministically; the LLM never chooses enforcement."""
    risk_level = risk_assessment.get("risk_level")
    findings = security_results.get("findings", [])
    has_critical = any(isinstance(item, dict) and item.get("severity") == "critical" for item in findings)
    scanner_warnings = (scanner_results or {}).get("warnings", [])
    has_scanner_warning = bool(scanner_warnings)

    if risk_level in {"critical", "high"} or has_critical:
        return "block"
    if has_scanner_warning and risk_level == "low":
        return "require_approval"
    if risk_level == "medium":
        return "require_approval"
    if risk_level == "low":
        return "allow"
    raise ValueError("risk assessment has no supported risk_level")
