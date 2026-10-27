"""Tests for configurable zone trust."""

import json

import pytest

from ai.astar import permit_risk
from ai.genetic import optimize_rules
from core.checks import (
    DEFAULT_ZONE_TRUST,
    ProblemType,
    ZoneTrust,
    analyze_rules,
    load_zone_trust,
)
from tests.helpers import make_rule


def test_custom_zone_trust_changes_trust_boundary_findings_and_risk() -> None:
    rule = make_rule(
        "dmz-to-database",
        src_zone="web",
        dst_zone="Database",
    )
    custom_trust = ZoneTrust(
        untrusted=frozenset({"WEB"}),
        trusted=frozenset({"database"}),
    )

    default_findings = analyze_rules([rule])
    custom_findings = analyze_rules([rule], custom_trust)

    assert not any(
        item.problem_type is ProblemType.UNTRUSTED_TO_TRUSTED
        for item in default_findings
    )
    assert any(
        item.problem_type is ProblemType.UNTRUSTED_TO_TRUSTED
        for item in custom_findings
    )
    assert permit_risk(rule, custom_trust) == permit_risk(rule) + 5


def test_default_zone_trust_moves_web_to_neutral() -> None:
    assert "web" not in DEFAULT_ZONE_TRUST.trusted
    assert "web" not in DEFAULT_ZONE_TRUST.untrusted


def test_optimizer_risk_score_uses_custom_zone_trust() -> None:
    rule = make_rule("web-to-database", src_zone="web", dst_zone="Database")
    custom_trust = ZoneTrust(
        untrusted=frozenset({"web"}),
        trusted=frozenset({"database"}),
    )

    default_result = optimize_rules([rule], random_packet_count=0)
    custom_result = optimize_rules(
        [rule],
        random_packet_count=0,
        zone_trust=custom_trust,
    )

    assert custom_result.before_risk_score == default_result.before_risk_score + 5


def test_load_zone_trust_parses_case_insensitively(tmp_path) -> None:
    path = tmp_path / "trust.json"
    path.write_text(
        json.dumps({"untrusted": ["Outside"], "trusted": ["Core"]}),
        encoding="utf-8",
    )

    trust = load_zone_trust(path)

    assert trust.untrusted == frozenset({"outside"})
    assert trust.trusted == frozenset({"core"})


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{invalid", "Invalid zone trust JSON"),
        ('{"untrusted": ["web"], "trusted": ["WEB"]}', "both untrusted and trusted"),
        ('{"untrusted": "web", "trusted": []}', "'untrusted' must be a list"),
    ],
)
def test_load_zone_trust_reports_invalid_json(tmp_path, content: str, message: str) -> None:
    path = tmp_path / "trust.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_zone_trust(path)
