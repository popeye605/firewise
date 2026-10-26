"""Shared small constructors for tests."""

import ipaddress

from core.models import Action, PortRange, Rule, ServiceMatch


def make_rule(
    rule_id: str,
    *,
    src_zone: str = "LAN",
    dst_zone: str = "WAN",
    src_ip: str = "10.0.0.0/24",
    dst_ip: str = "192.0.2.0/24",
    protocol: str = "tcp",
    ports: tuple[PortRange, ...] = (PortRange(443, 443),),
    action: Action = Action.PERMIT,
    log: bool = True,
) -> Rule:
    """Build a rule fixture, translating the loader's any token."""
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
