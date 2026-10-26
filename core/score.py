"""Severity-weighted firewall health scoring."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable

from core.checks import Finding, ProblemType, Severity, analyze_rules
from core.models import Rule

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
}
MAX_PENALTY_PER_RULE = SEVERITY_WEIGHTS[Severity.HIGH]


@dataclass(frozen=True, slots=True)
class HealthScore:
    """Score and breakdown that make the calculation auditable."""

    score: int
    penalty_points: int
    maximum_points: int
    findings_count: int
    severity_counts: dict[str, int]
    problem_counts: dict[str, int]


def calculate_health_score(
    rules: Iterable[Rule],
    findings: Iterable[Finding] | None = None,
) -> HealthScore:
    """Calculate a 0-100 score, capping combined penalties per affected rule.

    Each rule contributes at most 10 penalty points, even if several findings
    overlap. High, medium, and low findings contribute 10, 5, and 2 points
    respectively before that per-rule cap is applied. Scores are rounded to the
    nearest integer and an empty policy is rejected rather than scored as healthy.
    """
    ordered_rules = list(rules)
    if not ordered_rules:
        raise ValueError("Cannot calculate a health score for an empty rule list.")

    rule_ids = {rule.id for rule in ordered_rules}
    rule_findings = list(findings) if findings is not None else analyze_rules(ordered_rules)
    unknown_ids = sorted({finding.rule_id for finding in rule_findings} - rule_ids)
    if unknown_ids:
        raise ValueError(
            "Findings reference rules absent from the scored policy: "
            + ", ".join(unknown_ids)
        )

    points_by_rule: dict[str, int] = defaultdict(int)
    severity_counts: Counter[str] = Counter()
    problem_counts: Counter[str] = Counter()
    for finding in rule_findings:
        points_by_rule[finding.rule_id] += SEVERITY_WEIGHTS[finding.severity]
        severity_counts[finding.severity.value] += 1
        problem_counts[finding.problem_type.value] += 1

    penalty_points = sum(
        min(rule_points, MAX_PENALTY_PER_RULE)
        for rule_points in points_by_rule.values()
    )
    maximum_points = len(ordered_rules) * MAX_PENALTY_PER_RULE
    score = round(100 * (1 - penalty_points / maximum_points))
    return HealthScore(
        score=max(0, min(100, score)),
        penalty_points=penalty_points,
        maximum_points=maximum_points,
        findings_count=len(rule_findings),
        severity_counts=dict(severity_counts),
        problem_counts=dict(problem_counts),
    )
