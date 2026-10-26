"""Tests for explainable firewall problem checks."""

import ipaddress

import pytest

from core.checks import Finding, ProblemType, Severity, analyze_rules
from core.loader import load_demo_rules
from core.models import Action, PortRange, Rule, ServiceMatch


def make_rule(
    rule_id: str,
    *,
    src_zone: str = "LAN",
    dst_zone: str = "DB",
    src_ip: str = "10.0.0.0/24",
    dst_ip: str = "192.0.2.0/24",
    protocol: str = "tcp",
    ports: tuple[PortRange, ...] = (PortRange(443, 443),),
    action: Action = Action.PERMIT,
    log: bool = True,
) -> Rule:
    """Build a short test rule with configurable match attributes."""
    source_networks = (
        (ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0"))
        if src_ip.lower() == "any"
        else (ipaddress.ip_network(src_ip),)
    )
    destination_networks = (
        (ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0"))
        if dst_ip.lower() == "any"
        else (ipaddress.ip_network(dst_ip),)
    )
    return Rule(
        id=rule_id,
        src_zone=src_zone,
        dst_zone=dst_zone,
        src_networks=source_networks,
        dst_networks=destination_networks,
        service=ServiceMatch(protocol, ports),
        action=action,
        log=log,
    )


def test_demo_reports_planted_any_any_unlogged_duplicate_and_shadow_findings() -> None:
    findings = analyze_rules(load_demo_rules())

    assert sum(item.problem_type is ProblemType.ANY_ANY for item in findings) >= 3
    assert sum(item.problem_type is ProblemType.SHADOWED for item in findings) >= 5
    assert sum(item.problem_type is ProblemType.DUPLICATE for item in findings) >= 4
    assert sum(item.problem_type is ProblemType.UNLOGGED_PERMIT for item in findings) >= 6
    assert sum(
        item.problem_type is ProblemType.UNTRUSTED_TO_TRUSTED for item in findings
    ) >= 1
    assert all(item.explanation and item.suggested_fix for item in findings)


def test_any_any_requires_wildcard_addresses_and_any_service() -> None:
    findings = analyze_rules(
        [
            make_rule(
                "broad",
                src_ip="any",
                dst_ip="any",
                protocol="any",
                ports=(),
            ),
            make_rule("narrow", src_ip="any"),
        ]
    )

    assert [item.problem_type for item in findings].count(ProblemType.ANY_ANY) == 1
    assert findings[0].rule_id == "broad"


def test_shadow_detection_checks_zone_action_and_service_coverage() -> None:
    broad = make_rule("broad", src_ip="10.0.0.0/23", ports=(PortRange(400, 500),))
    covered = make_rule(
        "covered",
        src_ip="10.0.1.0/24",
        ports=(PortRange(443, 443),),
        action=Action.DENY,
    )
    other_zone = make_rule(
        "other-zone", src_ip="10.0.1.0/24", src_zone="VPN"
    )
    findings = analyze_rules([broad, covered, other_zone])

    shadow_findings = [
        item for item in findings if item.problem_type is ProblemType.SHADOWED
    ]
    assert len(shadow_findings) == 1
    assert shadow_findings[0].rule_id == "covered"
    assert shadow_findings[0].related_rule_ids == ("broad",)


def test_union_of_networks_and_port_ranges_can_cover_a_rule() -> None:
    first = make_rule(
        "first",
        src_ip="10.0.0.0/25",
        ports=(PortRange(400, 449),),
    )
    second = make_rule(
        "second",
        src_ip="10.0.0.128/25",
        ports=(PortRange(450, 500),),
    )
    target = make_rule(
        "target",
        src_ip="10.0.0.0/24",
        ports=(PortRange(400, 500),),
    )

    # Neither prior rule alone covers the target; these must not be combined
    # to claim that a single earlier rule fully shadows it.
    findings = analyze_rules([first, second, target])
    assert not any(
        item.rule_id == "target" and item.problem_type is ProblemType.SHADOWED
        for item in findings
    )


def test_earlier_rule_can_cover_multiple_networks_and_service_ranges() -> None:
    broad = make_rule(
        "broad",
        src_ip="10.0.0.0/23",
        ports=(PortRange(400, 500),),
    )
    target = Rule(
        id="target",
        src_zone="LAN",
        dst_zone="DB",
        src_networks=(
            ipaddress.ip_network("10.0.0.0/24"),
            ipaddress.ip_network("10.0.1.0/24"),
        ),
        dst_networks=(ipaddress.ip_network("192.0.2.0/24"),),
        service=ServiceMatch("tcp", (PortRange(400, 449), PortRange(450, 500))),
        action=Action.DENY,
        log=True,
    )

    findings = analyze_rules([broad, target])
    assert any(
        item.rule_id == "target" and item.problem_type is ProblemType.SHADOWED
        for item in findings
    )


@pytest.mark.parametrize(
    ("src_zone", "dst_zone", "action", "expected"),
    [
        ("Internet", "Database", Action.PERMIT, True),
        ("internet", "DATABASE", Action.PERMIT, True),
        ("LAN", "Database", Action.PERMIT, False),
        ("Internet", "Database", Action.DENY, False),
    ],
)
def test_zone_risk_classification_is_case_insensitive(
    src_zone: str,
    dst_zone: str,
    action: Action,
    expected: bool,
) -> None:
    findings = analyze_rules(
        [make_rule("rule", src_zone=src_zone, dst_zone=dst_zone, action=action)]
    )

    assert any(
        item.problem_type is ProblemType.UNTRUSTED_TO_TRUSTED for item in findings
    ) is expected


def test_zone_sets_can_be_configured_for_local_naming() -> None:
    findings = analyze_rules(
        [make_rule("rule", src_zone="outside", dst_zone="core")],
        untrusted_zones={"outside"},
        trusted_zones={"core"},
    )

    assert findings[0].problem_type is ProblemType.UNTRUSTED_TO_TRUSTED


def test_duplicate_is_reported_for_later_entry_with_reference() -> None:
    findings = analyze_rules([make_rule("first"), make_rule("copy", log=False)])
    duplicate = next(item for item in findings if item.problem_type is ProblemType.DUPLICATE)

    assert duplicate.rule_id == "copy"
    assert duplicate.related_rule_ids == ("first",)
    assert duplicate.severity is Severity.LOW
    assert isinstance(duplicate, Finding)
