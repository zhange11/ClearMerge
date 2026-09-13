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
    hard_blocks = risk_assessment.get("hard_blocks", [])
    factors = risk_assessment.get("factors", [])
    has_approval_factor = any(
        isinstance(factor, dict)
        and factor.get("code") in {"suspicious_diff_content", "security_tool_unavailable", "tool_warning"}
        for factor in factors
    )

    if hard_blocks or risk_level in {"critical", "high"} or has_critical:
        return "block"
    if (has_scanner_warning or has_approval_factor) and risk_level == "low":
        return "require_approval"
    if risk_level == "medium":
        return "require_approval"
    if risk_level == "low":
        return "allow"
    raise ValueError("risk assessment has no supported risk_level")
