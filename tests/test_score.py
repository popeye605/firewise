"""Tests for explainable, capped firewall health scoring."""

import ipaddress
import pytest

from core.checks import Finding, ProblemType, Severity, analyze_rules
from core.loader import load_demo_rules
from core.models import Action, PortRange, Rule, ServiceMatch
from core.score import (
    MAX_PENALTY_PER_RULE,
    SEVERITY_WEIGHTS,
    HealthScore,
    calculate_health_score,
)


def make_rule(rule_id: str, *, src_zone: str = "LAN", dst_zone: str = "WAN") -> Rule:
    """Create a basic rule for scoring tests."""
    return Rule(
        id=rule_id,
        src_zone=src_zone,
        dst_zone=dst_zone,
        src_networks=(ipaddress.ip_network("10.0.0.0/24"),),
        dst_networks=(ipaddress.ip_network("192.0.2.0/24"),),
        service=ServiceMatch("tcp", (PortRange(443, 443),)),
        action=Action.PERMIT,
        log=True,
    )


def make_finding(
    rule_id: str,
    severity: Severity,
    problem_type: ProblemType = ProblemType.ANY_ANY,
) -> Finding:
    """Create a finding to test the scoring formula independently."""
    return Finding(
        rule_id=rule_id,
        problem_type=problem_type,
        severity=severity,
        explanation="test explanation",
        suggested_fix="test fix",
    )


def test_clean_policy_scores_one_hundred() -> None:
    rules = [make_rule("clean", src_zone="LAN", dst_zone="WAN")]

    result = calculate_health_score(rules, findings=[])

    assert result.score == 100
    assert result.penalty_points == 0
    assert result.maximum_points == MAX_PENALTY_PER_RULE
    assert result.findings_count == 0


def test_severity_weights_are_applied_and_score_is_rounded() -> None:
    rules = [make_rule("high"), make_rule("medium"), make_rule("low")]
    findings = [
        make_finding("high", Severity.HIGH),
        make_finding("medium", Severity.MEDIUM),
        make_finding("low", Severity.LOW),
    ]

    result = calculate_health_score(rules, findings)

    expected_penalty = sum(SEVERITY_WEIGHTS.values())
    assert result.penalty_points == expected_penalty
    assert result.maximum_points == 3 * MAX_PENALTY_PER_RULE
    assert result.score == round(100 * (1 - expected_penalty / 30))
    assert result.severity_counts == {"High": 1, "Medium": 1, "Low": 1}


def test_penalty_for_overlapping_findings_is_capped_per_rule() -> None:
    rules = [make_rule("many"), make_rule("clean")]
    findings = [
        make_finding("many", Severity.HIGH),
        make_finding("many", Severity.MEDIUM, ProblemType.SHADOWED),
        make_finding("many", Severity.LOW, ProblemType.DUPLICATE),
    ]

    result = calculate_health_score(rules, findings)

    assert result.penalty_points == MAX_PENALTY_PER_RULE
    assert result.score == 50
    assert result.findings_count == 3
    assert result.problem_counts == {
        "Any-Any rule": 1,
        "Shadowed rule": 1,
        "Duplicate rule": 1,
    }


def test_score_uses_actual_demo_findings() -> None:
    rules = load_demo_rules()
    findings = analyze_rules(rules)

    result = calculate_health_score(rules, findings)

    assert 0 <= result.score <= 100
    assert result.findings_count == len(findings)
    assert result.maximum_points == len(rules) * MAX_PENALTY_PER_RULE
    assert result.problem_counts["Any-Any rule"] == 3


def test_empty_policy_is_rejected() -> None:
    with pytest.raises(ValueError, match="empty rule list"):
        calculate_health_score([])


def test_findings_for_unknown_rule_are_rejected() -> None:
    with pytest.raises(ValueError, match="absent from the scored policy"):
        calculate_health_score(
            [make_rule("known")],
            [make_finding("missing", Severity.HIGH)],
        )
