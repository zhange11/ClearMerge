from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, TypedDict

from ..llm.safety import sanitize_for_gemini
from .state import ReviewState

RiskLevel = Literal["low", "medium", "high", "critical"]
Recommendation = Literal["allow", "require_approval", "block"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class RiskFactor(TypedDict):
    code: str
    category: str
    severity: Severity
    impact: int
    evidence_ref: str
    explanation: str
    hard_block: bool


class RiskAssessment(TypedDict):
    score: int
    risk_level: RiskLevel
    recommendation: Recommendation
    factors: list[RiskFactor]
    hard_blocks: list[str]
    uncertainty: Literal["low", "medium", "high"]
    confidence: float
    required_actions: list[str]
    policy_version: str
    scorer_version: str
    commit_sha: str

RiskModel = Callable[[dict[str, Any]], dict[str, Any]]

_IMPACT_BY_SEVERITY = {"info": 0, "low": 5, "medium": 20, "high": 35, "critical": 70}


def collect_risk_factors(state: ReviewState) -> list[RiskFactor]:
    """Normalize all current scanner, security, and content evidence."""
    factors: list[RiskFactor] = []
    seen: set[str] = set()

    def add(factor: RiskFactor) -> None:
        key = factor["evidence_ref"]
        if key in seen:
            return
        seen.add(key)
        factors.append(factor)

    scanner = state.get("scanner_results", {})
    for finding in _dict_items(scanner.get("findings")):
        category = str(finding.get("category", "verification"))
        severity = _severity(finding.get("severity"))
        add(_finding_factor(finding, category, severity, f"scanner:{finding.get('id', len(factors))}"))
    for check in _dict_items(scanner.get("checks")):
        status = check.get("status")
        if status in {"failed", "timed_out"}:
            category = str(check.get("category", "verification"))
            severity: Severity = "high" if status == "timed_out" else ("high" if category == "dependencies" else "medium")
            add({
                "code": "check_timeout" if status == "timed_out" else "failing_check",
                "category": category,
                "severity": severity,
                "impact": 15 if status == "timed_out" else 25,
                "evidence_ref": f"scanner:check:{check.get('name', len(factors))}",
                "explanation": f"{check.get('name', 'check')} reported {status}.",
                "hard_block": False,
            })
    for warning in _dict_items(scanner.get("warnings")):
        add(_warning_factor(warning, "tooling", f"scanner-warning:{warning.get('code', len(factors))}"))

    security = state.get("security_results", {})
    for finding in _dict_items(security.get("findings")):
        severity = _severity(finding.get("severity"))
        tool = str(finding.get("tool", "security"))
        secret = tool == "gitleaks" or "secret" in str(finding.get("title", "")).lower()
        add(_finding_factor(
            finding,
            "security",
            severity,
            f"security:{finding.get('id', len(factors))}",
            hard_block=secret and severity in {"high", "critical"} or severity == "critical",
        ))
    for warning in _dict_items(security.get("warnings")):
        add(_warning_factor(warning, "tooling", f"security-warning:{warning.get('tool', len(factors))}"))

    if state.get("suspicious_diff_content"):
        add({
            "code": "suspicious_diff_content",
            "category": "content",
            "severity": "medium",
            "impact": 20,
            "evidence_ref": "content-guard",
            "explanation": "PR content resembles instructions aimed at an LLM.",
            "hard_block": False,
        })
    return factors


def calculate_deterministic_score(state: ReviewState, factors: list[RiskFactor]) -> RiskAssessment:
    score = min(100, max(0, sum(factor["impact"] for factor in factors)))
    hard_blocks = [factor["code"] for factor in factors if factor["hard_block"]]
    if hard_blocks:
        level: RiskLevel = "critical"
        recommendation: Recommendation = "block"
    elif score >= 80:
        level, recommendation = "critical", "block"
    elif score >= 60:
        level, recommendation = "high", "block"
    elif score >= 25:
        level, recommendation = "medium", "require_approval"
    else:
        level, recommendation = "low", "allow"
    uncertainty: Literal["low", "medium", "high"] = "medium" if any(f["code"] in {"check_timeout", "security_tool_unavailable"} for f in factors) else "low"
    return {
        "score": score,
        "risk_level": level,
        "recommendation": recommendation,
        "factors": factors,
        "hard_blocks": hard_blocks,
        "uncertainty": uncertainty,
        "confidence": 0.7 if uncertainty == "medium" else 1.0,
        "required_actions": [factor["explanation"] for factor in factors if factor["severity"] in {"high", "critical"}],
        "policy_version": "1.0",
        "scorer_version": "deterministic-1.0",
        "commit_sha": state.get("commit_sha", ""),
    }


def score_risk(state: ReviewState, model: RiskModel | None = None) -> RiskAssessment:
    factors = collect_risk_factors(state)
    baseline = calculate_deterministic_score(state, factors)
    if model is None:
        return baseline
    prompt_payload = sanitize_for_gemini({
        "commit_sha": state.get("commit_sha"),
        "baseline": baseline,
        "factors": factors,
    })
    try:
        candidate = model(prompt_payload)
        assessment = validate_risk_assessment(candidate, baseline)
    except (TypeError, ValueError, KeyError):
        return baseline
    return assessment


def validate_risk_assessment(candidate: dict[str, Any], baseline: RiskAssessment) -> RiskAssessment:
    score = candidate.get("score")
    level = candidate.get("risk_level")
    recommendation = candidate.get("recommendation")
    if not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("risk score must be an integer from 0 to 100")
    if level not in {"low", "medium", "high", "critical"}:
        raise ValueError("unsupported risk level")
    if recommendation not in {"allow", "require_approval", "block"}:
        raise ValueError("unsupported recommendation")
    if baseline["hard_blocks"] and recommendation != "block":
        raise ValueError("model cannot override hard blocks")
    return {
        **baseline,
        **candidate,
        "score": score,
        "risk_level": level,
        "recommendation": recommendation,
        "hard_blocks": baseline["hard_blocks"],
        "factors": baseline["factors"],
        "commit_sha": baseline["commit_sha"],
    }


def _finding_factor(finding: dict[str, Any], category: str, severity: Severity, reference: str, hard_block: bool = False) -> RiskFactor:
    return {
        "code": str(finding.get("code") or finding.get("id") or "finding"),
        "category": category,
        "severity": severity,
        "impact": _IMPACT_BY_SEVERITY[severity],
        "evidence_ref": reference,
        "explanation": str(finding.get("description") or finding.get("title") or "Finding reported by a check.")[:500],
        "hard_block": hard_block,
    }


def _warning_factor(warning: dict[str, Any], category: str, reference: str) -> RiskFactor:
    return {
        "code": str(warning.get("code") or "tool_warning"),
        "category": category,
        "severity": "medium",
        "impact": 10,
        "evidence_ref": reference,
        "explanation": str(warning.get("message") or "Required evidence is unavailable.")[:500],
        "hard_block": False,
    }


def _severity(value: Any) -> Severity:
    return value if value in {"info", "low", "medium", "high", "critical"} else "medium"


def _dict_items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
