"""Explainable checks for common firewall policy problems."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from core.models import IPAddressNetwork, PortRange, Rule, ServiceMatch


class Severity(str, Enum):
    """User-facing severity level for a finding."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ProblemType(str, Enum):
    """Supported firewall-rule finding categories."""

    ANY_ANY = "Any-Any rule"
    SHADOWED = "Shadowed rule"
    DUPLICATE = "Duplicate rule"
    UNLOGGED_PERMIT = "Unlogged permit"
    UNTRUSTED_TO_TRUSTED = "Untrusted-to-trusted permit"


@dataclass(frozen=True, slots=True)
class Finding:
    """A detected issue and its plain-English remediation guidance."""

    rule_id: str
    problem_type: ProblemType
    severity: Severity
    explanation: str
    suggested_fix: str
    related_rule_ids: tuple[str, ...] = ()


DEFAULT_UNTRUSTED_ZONES = frozenset({"internet", "guest", "vendor", "untrusted"})
DEFAULT_TRUSTED_ZONES = frozenset(
    {"internal", "database", "management", "network", "storage", "artifact", "web", "services"}
)
_WILDCARD_NETWORKS = frozenset({"0.0.0.0/0", "::/0"})


def _network_set_covers(
    covering: tuple[IPAddressNetwork, ...],
    covered: tuple[IPAddressNetwork, ...],
) -> bool:
    """Return whether a union of networks contains every target network."""
    for target in covered:
        target_start = int(target.network_address)
        target_end = int(target.broadcast_address)
        intervals = sorted(
            (
                int(network.network_address),
                int(network.broadcast_address),
            )
            for network in covering
            if network.version == target.version
            and int(network.network_address) <= target_end
            and int(network.broadcast_address) >= target_start
        )
        next_address = target_start
        for start, end in intervals:
            if start > next_address:
                break
            next_address = max(next_address, end + 1)
            if next_address > target_end:
                break
        if next_address <= target_end:
            return False
    return True


def _range_set_covers(
    covering: tuple[PortRange, ...],
    covered: tuple[PortRange, ...],
) -> bool:
    """Return whether a union of inclusive port intervals covers each target."""
    for target in covered:
        next_port = target.start
        for interval in sorted(covering, key=lambda item: item.start):
            if interval.end < next_port:
                continue
            if interval.start > next_port:
                break
            next_port = max(next_port, interval.end + 1)
            if next_port > target.end:
                break
        if next_port <= target.end:
            return False
    return True


def _service_covers(covering: ServiceMatch, covered: ServiceMatch) -> bool:
    """Return whether one service match includes another service match."""
    if covering.protocol == "any":
        return True
    if covering.protocol != covered.protocol:
        return False
    if not covering.ports:
        return True
    if not covered.ports:
        return False
    return _range_set_covers(covering.ports, covered.ports)


def _rule_covers(covering: Rule, covered: Rule) -> bool:
    """Check whether a prior rule matches every packet matched by another."""
    return (
        covering.src_zone.casefold() == covered.src_zone.casefold()
        and covering.dst_zone.casefold() == covered.dst_zone.casefold()
        and _network_set_covers(covering.src_networks, covered.src_networks)
        and _network_set_covers(covering.dst_networks, covered.dst_networks)
        and _service_covers(covering.service, covered.service)
    )


def _same_match(first: Rule, second: Rule) -> bool:
    """Compare match conditions and action, excluding identity and logging."""
    return (
        first.src_zone.casefold() == second.src_zone.casefold()
        and first.dst_zone.casefold() == second.dst_zone.casefold()
        and first.src_networks == second.src_networks
        and first.dst_networks == second.dst_networks
        and first.service == second.service
        and first.action == second.action
    )


def _is_any_any(rule: Rule) -> bool:
    """Identify rules with unrestricted source, destination, and service."""
    return (
        all(str(network) in _WILDCARD_NETWORKS for network in rule.src_networks)
        and all(str(network) in _WILDCARD_NETWORKS for network in rule.dst_networks)
        and rule.service.protocol == "any"
    )


def _zone_names(zones: Iterable[str]) -> frozenset[str]:
    """Normalize zone names for case-insensitive policy classification."""
    return frozenset(zone.strip().casefold() for zone in zones)


def analyze_rules(
    rules: Iterable[Rule],
    *,
    untrusted_zones: Iterable[str] = DEFAULT_UNTRUSTED_ZONES,
    trusted_zones: Iterable[str] = DEFAULT_TRUSTED_ZONES,
) -> list[Finding]:
    """Find risky and redundant rules in their original first-match order.

    Shadowing is reported when one earlier rule, on the same zone pair,
    completely covers a later rule's addresses and service. Zone classification
    uses the supplied sets; the defaults are conventional demo names and should
    be customized for real environments.
    """
    ordered_rules = list(rules)
    untrusted = _zone_names(untrusted_zones)
    trusted = _zone_names(trusted_zones)
    findings: list[Finding] = []

    for index, rule in enumerate(ordered_rules):
        if _is_any_any(rule):
            findings.append(
                Finding(
                    rule_id=rule.id,
                    problem_type=ProblemType.ANY_ANY,
                    severity=Severity.HIGH,
                    explanation=(
                        "This rule matches every source, destination, and service "
                        "in its zone pair, creating an exceptionally broad policy."
                    ),
                    suggested_fix=(
                        "Replace the wildcards with the smallest required source "
                        "and destination networks and explicitly allowed services."
                    ),
                )
            )

        if rule.action.value == "permit" and not rule.log:
            findings.append(
                Finding(
                    rule_id=rule.id,
                    problem_type=ProblemType.UNLOGGED_PERMIT,
                    severity=Severity.MEDIUM,
                    explanation=(
                        "Allowed traffic matched by this rule is not logged, "
                        "reducing visibility during audits and incident response."
                    ),
                    suggested_fix=(
                        "Enable logging after checking the expected event volume "
                        "and your organization's logging policy."
                    ),
                )
            )

        if (
            rule.action.value == "permit"
            and rule.src_zone.casefold() in untrusted
            and rule.dst_zone.casefold() in trusted
        ):
            findings.append(
                Finding(
                    rule_id=rule.id,
                    problem_type=ProblemType.UNTRUSTED_TO_TRUSTED,
                    severity=Severity.HIGH,
                    explanation=(
                        f"This permit allows traffic from the untrusted "
                        f"{rule.src_zone} zone into the trusted {rule.dst_zone} zone."
                    ),
                    suggested_fix=(
                        "Confirm the business need, narrow the permitted networks "
                        "and service, and consider a more restricted intermediary zone."
                    ),
                )
            )

        prior_matches = [
            previous
            for previous in ordered_rules[:index]
            if _same_match(previous, rule)
        ]
        if prior_matches:
            findings.append(
                Finding(
                    rule_id=rule.id,
                    problem_type=ProblemType.DUPLICATE,
                    severity=Severity.LOW,
                    explanation=(
                        "An earlier rule has the same zones, match conditions, "
                        "and action; this repeated entry adds no distinct decision."
                    ),
                    suggested_fix=(
                        "Review references and logging needs, then remove the "
                        "duplicate if it is not required for documentation."
                    ),
                    related_rule_ids=(prior_matches[0].id,),
                )
            )
            continue

        covering_rule = next(
            (
                previous
                for previous in ordered_rules[:index]
                if _rule_covers(previous, rule)
            ),
            None,
        )
        if covering_rule is not None:
            findings.append(
                Finding(
                    rule_id=rule.id,
                    problem_type=ProblemType.SHADOWED,
                    severity=Severity.MEDIUM,
                    explanation=(
                        f"Earlier rule {covering_rule.id} matches all traffic "
                        "covered by this rule, so this rule is never reached."
                    ),
                    suggested_fix=(
                        "Review the earlier rule and intended policy; remove the "
                        "unreachable rule or narrow/reorder rules with care."
                    ),
                    related_rule_ids=(covering_rule.id,),
                )
            )
    return findings
