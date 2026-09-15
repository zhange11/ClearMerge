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
_MAX_TEXT_LENGTH = 500
_RECOMMENDATION_RANK = {"allow": 0, "require_approval": 1, "block": 2}


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

    policy = state.get("repository_policy", {})
    scanner = state.get("scanner_results", {})
    for finding in _dict_items(scanner.get("findings")):
        category = str(finding.get("category", "verification"))
        severity = _severity(finding.get("severity"))
        impact = _IMPACT_BY_SEVERITY[severity]
        if category in {"dependency", "dependencies"}:
            impact = 20 if severity in {"high", "critical"} else 10 if severity == "medium" else 5
        sensitive_test = category == "tests" and (
            bool(finding.get("sensitive_area"))
            or bool(finding.get("sensitive"))
            or bool(finding.get("affected_sensitive_area"))
        )
        if sensitive_test:
            impact = 35
        add(_finding_factor(finding, category, severity, f"scanner:{finding.get('id', len(factors))}", impact=impact))
    for check in _dict_items(scanner.get("checks")):
        status = check.get("status")
        if status in {"failed", "timed_out"}:
            category = str(check.get("category", "verification"))
            sensitive_check = bool(check.get("sensitive_area")) or bool(check.get("sensitive"))
            severity: Severity = "high" if status == "timed_out" else ("high" if category in {"dependency", "dependencies"} else "medium")
            impact = 15 if status == "timed_out" else 20 if category in {"dependency", "dependencies"} else 35 if sensitive_check else 25
            add({
                "code": "check_timeout" if status == "timed_out" else "failing_check",
                "category": category,
                "severity": severity,
                "impact": impact,
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
            hard_block=(
                secret and severity in {"high", "critical"}
                or severity == "critical"
                or (bool(policy.get("block_high_findings", False)) and severity == "high")
            ),
        ))
    for warning in _dict_items(security.get("warnings")):
        add(_warning_factor(warning, "tooling", f"security-warning:{warning.get('tool', len(factors))}"))

    for tool in _dict_items(security.get("tools")):
        tool_status = tool.get("status")
        error = str(tool.get("error", "")).lower()
        if tool_status == "failed" or "timeout" in error or "parse" in error:
            add({
                "code": "security_tool_timeout" if "timeout" in error else "security_tool_parser_failure" if "parse" in error else "security_tool_failed",
                "category": "tooling",
                "severity": "high",
                "impact": 15,
                "evidence_ref": f"security-tool:{tool.get('tool', len(factors))}",
                "explanation": f"Security tool {tool.get('tool', 'unknown')} did not produce clean evidence.",
                "hard_block": False,
            })

    required_tools = policy.get("required_security_tools", [])
    tool_results = {
        str(tool.get("tool")): tool
        for tool in _dict_items(security.get("tools"))
    }
    for required_tool in required_tools if isinstance(required_tools, list) else []:
        tool = tool_results.get(str(required_tool))
        unavailable = tool is None or tool.get("status") in {"warning", "failed"} or "parse" in str(tool.get("error", "")).lower()
        if unavailable:
            add({
                "code": "required_security_scan_missing",
                "category": "tooling",
                "severity": "critical",
                "impact": 25,
                "evidence_ref": f"required-security-tool:{required_tool}",
                "explanation": f"Required security tool {required_tool} did not produce valid evidence.",
                "hard_block": True,
            })

    if state.get("suspicious_diff_content"):
        suspicious_hard_block = bool(policy.get("block_suspicious_content", False))
        add({
            "code": "suspicious_diff_content",
            "category": "content",
            "severity": "medium",
            "impact": 20,
            "evidence_ref": "content-guard",
            "explanation": "PR content resembles instructions aimed at an LLM.",
            "hard_block": suspicious_hard_block,
        })
    if state.get("status") == "superseded" or state.get("latest_commit_sha", state.get("commit_sha")) != state.get("commit_sha"):
        add({
            "code": "stale_review_evidence",
            "category": "verification",
            "severity": "critical",
            "impact": 100,
            "evidence_ref": "review:commit",
            "explanation": "Review evidence is stale or belongs to a superseded commit.",
            "hard_block": True,
        })
    evidence_sha = state.get("evidence_commit_sha")
    if evidence_sha and evidence_sha != state.get("commit_sha"):
        add({
            "code": "stale_review_evidence",
            "category": "verification",
            "severity": "critical",
            "impact": 100,
            "evidence_ref": "review:evidence-commit",
            "explanation": "Evidence does not belong to the reviewed commit.",
            "hard_block": True,
        })

    scope = state.get("change_scope", {})
    sensitive_areas = scope.get("sensitive_areas", [])
    if isinstance(sensitive_areas, list) and sensitive_areas:
        add({
            "code": "sensitive_area_change",
            "category": "change_scope",
            "severity": "medium",
            "impact": min(15 * len(sensitive_areas), 15),
            "evidence_ref": "scope:sensitive-areas",
            "explanation": f"Sensitive areas changed: {', '.join(str(area) for area in sensitive_areas[:10])}.",
            "hard_block": False,
        })
    if scope.get("dependency_manifest_changed"):
        add({
            "code": "dependency_manifest_change",
            "category": "change_scope",
            "severity": "medium",
            "impact": 10,
            "evidence_ref": "scope:dependency-manifest",
            "explanation": "A dependency manifest or lockfile changed.",
            "hard_block": False,
        })
    if scope.get("migration_changed") or scope.get("infrastructure_changed"):
        add({
            "code": "migration_or_infrastructure_change",
            "category": "change_scope",
            "severity": "medium",
            "impact": 15,
            "evidence_ref": "scope:migration-infrastructure",
            "explanation": "A migration or infrastructure file changed.",
            "hard_block": False,
        })
    changed_lines = scope.get("lines_added", 0) + scope.get("lines_deleted", 0)
    if isinstance(changed_lines, int) and changed_lines > 500:
        add({
            "code": "large_change",
            "category": "change_scope",
            "severity": "medium",
            "impact": 20 if changed_lines > 2000 else 10,
            "evidence_ref": "scope:changed-lines",
            "explanation": f"The change contains {changed_lines} added or deleted lines.",
            "hard_block": False,
        })
    if scope.get("behavior_change") and scope.get("tests_added") is False:
        add({
            "code": "no_tests_added",
            "category": "verification",
            "severity": "medium",
            "impact": 10,
            "evidence_ref": "scope:no-tests-added",
            "explanation": "A detectable behavior change has no added or updated tests.",
            "hard_block": False,
        })
    return factors


def calculate_deterministic_score(state: ReviewState, factors: list[RiskFactor]) -> RiskAssessment:
    score = min(100, max(0, sum(factor["impact"] for factor in factors)))
    hard_blocks = [factor["code"] for factor in factors if factor["hard_block"]]
    requires_approval = any(
        factor["code"] in {"suspicious_diff_content", "security_tool_unavailable", "tool_warning"}
        for factor in factors
    )
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
        level = "low"
        recommendation = "require_approval" if requires_approval else "allow"
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
    except (TypeError, ValueError, KeyError, AttributeError):
        if state.get("deterministic_fallback_available", True) is False:
            baseline["hard_blocks"].append("invalid_risk_assessment")
            baseline["recommendation"] = "block"
            baseline["risk_level"] = "critical"
            baseline["score"] = 100
        return baseline
    return assessment


def validate_risk_assessment(candidate: dict[str, Any], baseline: RiskAssessment) -> RiskAssessment:
    if not isinstance(candidate, dict):
        raise TypeError("risk model output must be an object")
    score = candidate.get("score")
    level = candidate.get("risk_level")
    recommendation = candidate.get("recommendation")
    if not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("risk score must be an integer from 0 to 100")
    if level not in {"low", "medium", "high", "critical"}:
        raise ValueError("unsupported risk level")
    if recommendation not in {"allow", "require_approval", "block"}:
        raise ValueError("unsupported recommendation")
    uncertainty = candidate.get("uncertainty", baseline["uncertainty"])
    if uncertainty not in {"low", "medium", "high"}:
        raise ValueError("unsupported uncertainty")
    confidence = candidate.get("confidence", baseline["confidence"])
    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError("confidence must be between 0 and 1")
    _validate_factors(baseline["factors"])
    _validate_factors(candidate.get("factors", baseline["factors"]))
    _validate_text_list(candidate.get("required_actions", baseline["required_actions"]), "required_actions")
    if baseline["hard_blocks"] and recommendation != "block":
        raise ValueError("model cannot override hard blocks")
    if _RECOMMENDATION_RANK[recommendation] < _RECOMMENDATION_RANK[baseline["recommendation"]]:
        raise ValueError("model recommendation weakens deterministic policy")
    if level in {"high", "critical"} and recommendation != "block":
        raise ValueError("high and critical risk must block")
    if level == "medium" and recommendation == "allow":
        raise ValueError("medium risk requires approval")
    return {
        **baseline,
        **candidate,
        "score": score,
        "risk_level": level,
        "recommendation": recommendation,
        "uncertainty": uncertainty,
        "confidence": confidence,
        "hard_blocks": baseline["hard_blocks"],
        "factors": baseline["factors"],
        "commit_sha": baseline["commit_sha"],
    }


def _validate_factors(factors: Any) -> None:
    if not isinstance(factors, list):
        raise ValueError("factors must be a list")
    for factor in factors:
        if not isinstance(factor, dict):
            raise ValueError("each factor must be an object")
        if not factor.get("evidence_ref"):
            raise ValueError("material factors require an evidence reference")
        if factor.get("severity") not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("factor has unsupported severity")
        impact = factor.get("impact")
        if not isinstance(impact, int) or impact < 0 or impact > 100:
            raise ValueError("factor impact must be an integer from 0 to 100")
        explanation = factor.get("explanation", "")
        if not isinstance(explanation, str) or len(explanation) > _MAX_TEXT_LENGTH:
            raise ValueError("factor explanation is too long")


def _validate_text_list(values: Any, field_name: str) -> None:
    if not isinstance(values, list) or len(values) > 20:
        raise ValueError(f"{field_name} must contain at most 20 items")
    if any(not isinstance(value, str) or len(value) > _MAX_TEXT_LENGTH for value in values):
        raise ValueError(f"{field_name} contains unbounded text")


def _finding_factor(
    finding: dict[str, Any],
    category: str,
    severity: Severity,
    reference: str,
    hard_block: bool = False,
    impact: int | None = None,
) -> RiskFactor:
    return {
        "code": str(finding.get("code") or finding.get("id") or "finding"),
        "category": category,
        "severity": severity,
        "impact": _IMPACT_BY_SEVERITY[severity] if impact is None else impact,
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
