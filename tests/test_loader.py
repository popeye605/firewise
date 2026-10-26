"""Tests for CSV rule loading and validation."""

from io import StringIO
from pathlib import Path

import pytest

from core.loader import RuleLoadError, load_demo_rules, load_rules
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
