"""Tests for CSV rule loading and validation."""

from io import StringIO
from pathlib import Path

import pytest

from core.checks import ProblemType, analyze_rules
from core.loader import (
    RuleLoadError,
    _parse_service,
    load_demo_rules,
    load_rules,
    load_rules_with_warnings,
)
from core.models import Action

HEADER = "id,src_zone,dst_zone,src_ip,dst_ip,service,action,log\n"
VALID_ROW = "r1,LAN,WAN,10.0.0.0/8,192.0.2.0/24,https,permit,true\n"


def test_load_rules_parses_normalized_rule_fields() -> None:
    rule = load_rules(StringIO(HEADER + VALID_ROW))[0]

    assert rule.id == "r1"
    assert rule.action is Action.PERMIT
    assert rule.service.protocol == "tcp"
    assert rule.service.ports[0].start == 443
    assert str(rule.src_networks[0]) == "10.0.0.0/8"


def test_load_rules_supports_any_for_both_ip_families() -> None:
    rule = load_rules(StringIO(HEADER + VALID_ROW.replace("10.0.0.0/8", "any")))[0]

    assert [str(network) for network in rule.src_networks] == ["0.0.0.0/0", "::/0"]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "missing a header"),
        ("id,src_zone\nr1,LAN\n", "missing required columns"),
        (HEADER + VALID_ROW.replace("10.0.0.0/8", "invalid"), "Invalid src_ip"),
        (HEADER + VALID_ROW.replace("permit", "maybe"), "Unsupported action"),
        (HEADER + VALID_ROW.replace("true", "sometimes"), "Invalid log value"),
        (HEADER + VALID_ROW + VALID_ROW.replace("r1", "r1"), "duplicate rule id"),
    ],
)
def test_load_rules_reports_invalid_input(content: str, message: str) -> None:
    with pytest.raises(RuleLoadError, match=message):
        load_rules(StringIO(content))


def test_load_rules_accepts_path(tmp_path: Path) -> None:
    csv_path = tmp_path / "rules.csv"
    csv_path.write_text(HEADER + VALID_ROW, encoding="utf-8")

    assert len(load_rules(csv_path)) == 1
    assert len(load_rules(str(csv_path))) == 1


@pytest.mark.parametrize(
    ("name", "protocol", "port"),
    [
        ("ftp", "tcp", 21),
        ("smtp", "tcp", 25),
        ("smtps", "tcp", 465),
        ("submission", "tcp", 587),
        ("imap", "tcp", 143),
        ("imaps", "tcp", 993),
        ("pop3", "tcp", 110),
        ("pop3s", "tcp", 995),
        ("mysql", "tcp", 3306),
        ("postgres", "tcp", 5432),
        ("mssql", "tcp", 1433),
        ("ldap", "tcp", 389),
        ("ldaps", "tcp", 636),
        ("smb", "tcp", 445),
        ("telnet", "tcp", 23),
        ("snmp", "udp", 161),
        ("syslog", "udp", 514),
    ],
)
def test_parse_service_supports_common_aliases(
    name: str,
    protocol: str,
    port: int,
) -> None:
    service = _parse_service(name)

    assert service.protocol == protocol
    assert [(item.start, item.end) for item in service.ports] == [(port, port)]


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_parse_service_supports_bare_protocols(protocol: str) -> None:
    service = _parse_service(protocol)

    assert service.protocol == protocol
    assert service.ports == ()


@pytest.mark.parametrize("separator", [";", "|", ","])
def test_parse_service_combines_same_protocol_lists(separator: str) -> None:
    service = _parse_service(f"tcp/80{separator}tcp/443")

    assert service.protocol == "tcp"
    assert [(item.start, item.end) for item in service.ports] == [(80, 80), (443, 443)]


def test_parse_service_accepts_quoted_comma_port_shorthand() -> None:
    quoted_row = (
        'r1,LAN,WAN,10.0.0.0/8,192.0.2.0/24,"tcp/80,443",permit,true\n'
    )
    service = load_rules(StringIO(HEADER + quoted_row))[0].service

    assert service.protocol == "tcp"
    assert [(item.start, item.end) for item in service.ports] == [(80, 80), (443, 443)]


def test_parse_service_rejects_mixed_protocol_lists() -> None:
    with pytest.raises(RuleLoadError, match="split the rule into one row per protocol"):
        _parse_service("tcp/80;udp/53")


def test_parse_service_rejects_reversed_port_ranges() -> None:
    with pytest.raises(RuleLoadError, match="Port range start cannot exceed its end"):
        _parse_service("tcp/80-70")


def test_multi_range_services_work_with_shadow_and_duplicate_checks() -> None:
    rows = (
        "first,LAN,WAN,10.0.0.0/24,192.0.2.0/24,tcp/80;tcp/443,permit,true\n"
        "duplicate,LAN,WAN,10.0.0.0/24,192.0.2.0/24,tcp/80;tcp/443,permit,true\n"
        "covered,LAN,WAN,10.0.0.0/24,192.0.2.0/24,tcp/443,permit,true\n"
    )
    findings = analyze_rules(load_rules(StringIO(HEADER + rows)))

    assert any(
        finding.rule_id == "duplicate"
        and finding.problem_type is ProblemType.DUPLICATE
        for finding in findings
    )
    assert any(
        finding.rule_id == "covered"
        and finding.problem_type is ProblemType.SHADOWED
        for finding in findings
    )


def test_load_rules_with_warnings_reports_normalization_and_preserves_old_api() -> None:
    content = (
        HEADER
        + " r1 ,LAN,WAN,10.0.0.5/24,0.0.0.0/0,https,permit,true\n"
    )

    rules, warnings = load_rules_with_warnings(StringIO(content))

    assert rules[0].id == "r1"
    assert str(rules[0].src_networks[0]) == "10.0.0.0/24"
    assert warnings == [
        "CSV line 2: rule id ' r1 ' had leading or trailing spaces; trimmed to 'r1'.",
        "CSV line 2: src_ip '10.0.0.5/24' has host bits set; treated as 10.0.0.0/24.",
        "CSV line 2: dst_ip '0.0.0.0/0' is a /0 network; consider writing 'any'.",
    ]
    assert load_rules(StringIO(content)) == rules


def test_load_rules_with_warnings_has_no_warnings_for_clean_file() -> None:
    rules, warnings = load_rules_with_warnings(StringIO(HEADER + VALID_ROW))

    assert len(rules) == 1
    assert warnings == []


def test_demo_dataset_has_expected_rule_count_and_planted_categories() -> None:
    rules = load_demo_rules()

    assert len(rules) == 40
    assert sum(
        all(str(network) in {"0.0.0.0/0", "::/0"} for network in rule.src_networks)
        and all(str(network) in {"0.0.0.0/0", "::/0"} for network in rule.dst_networks)
        and rule.service.protocol == "any"
        for rule in rules
    ) >= 3
    assert sum(rule.action is Action.PERMIT and not rule.log for rule in rules) >= 6
