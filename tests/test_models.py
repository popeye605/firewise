"""Tests for normalized firewall rule models."""

import ipaddress

import pytest

from core.models import Action, PortRange, Rule, ServiceMatch


def test_port_range_accepts_valid_inclusive_interval() -> None:
    assert PortRange(80, 81) == PortRange(80, 81)


@pytest.mark.parametrize(
    ("start", "end"),
    [(-1, 80), (0, 65536), (82, 81)],
)
def test_port_range_rejects_invalid_values(start: int, end: int) -> None:
    with pytest.raises(ValueError):
        PortRange(start, end)


def test_service_match_normalizes_protocol() -> None:
    assert ServiceMatch(" TCP ").protocol == "tcp"


def test_any_service_cannot_have_port_constraints() -> None:
    with pytest.raises(ValueError, match="cannot specify ports"):
        ServiceMatch("any", (PortRange(80, 80),))


def test_rule_strips_identifiers_and_requires_networks() -> None:
    rule = Rule(
        id=" r1 ",
        src_zone=" LAN ",
        dst_zone=" WAN ",
        src_networks=(ipaddress.ip_network("10.0.0.0/8"),),
        dst_networks=(ipaddress.ip_network("192.0.2.0/24"),),
        service=ServiceMatch("tcp", (PortRange(443, 443),)),
        action=Action.PERMIT,
        log=True,
    )
    assert (rule.id, rule.src_zone, rule.dst_zone) == ("r1", "LAN", "WAN")

    with pytest.raises(ValueError, match="source network"):
        Rule(
            id="r2",
            src_zone="LAN",
            dst_zone="WAN",
            src_networks=(),
            dst_networks=(ipaddress.ip_network("192.0.2.0/24"),),
            service=ServiceMatch("any"),
            action=Action.DENY,
            log=False,
        )
