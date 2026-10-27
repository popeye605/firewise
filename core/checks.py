"""Explainable checks for common firewall policy problems."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
import json
from pathlib import Path
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
    {"internal", "database", "management", "network", "storage", "artifact", "services"}
)
_WILDCARD_NETWORKS = frozenset({"0.0.0.0/0", "::/0"})


@dataclass(frozen=True, slots=True)
class ZoneTrust:
    """Case-insensitive trust classifications for network zones."""

    untrusted: frozenset[str]
    trusted: frozenset[str]

    def __post_init__(self) -> None:
        """Normalize names and reject conflicting trust classifications."""
        untrusted = frozenset(zone.strip().casefold() for zone in self.untrusted)
        trusted = frozenset(zone.strip().casefold() for zone in self.trusted)
        overlap = untrusted & trusted
        if overlap:
            raise ValueError(
                "Zones cannot be both untrusted and trusted: "
                + ", ".join(sorted(overlap))
            )
        object.__setattr__(self, "untrusted", untrusted)
        object.__setattr__(self, "trusted", trusted)


DEFAULT_ZONE_TRUST = ZoneTrust(DEFAULT_UNTRUSTED_ZONES, DEFAULT_TRUSTED_ZONES)


@lru_cache(maxsize=16_384)
def _network_bounds(network: IPAddressNetwork) -> tuple[int, int, int]:
    """Cache numeric inclusive network bounds for repeated coverage checks."""
    return (
        network.version,
        int(network.network_address),
        int(network.broadcast_address),
    )


def parse_zone_trust_json(content: str) -> ZoneTrust:
    """Parse and validate a JSON zone trust mapping."""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid zone trust JSON: {exc.msg} at line {exc.lineno}.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Invalid zone trust JSON: expected an object.")
    if set(payload) != {"untrusted", "trusted"}:
        raise ValueError(
            "Invalid zone trust JSON: expected exactly 'untrusted' and 'trusted' lists."
        )
    values: dict[str, frozenset[str]] = {}
    for key in ("untrusted", "trusted"):
        entries = payload[key]
        if not isinstance(entries, list) or not all(
            isinstance(entry, str) and entry.strip() for entry in entries
        ):
            raise ValueError(
                f"Invalid zone trust JSON: '{key}' must be a list of non-empty strings."
            )
        values[key] = frozenset(entries)
    try:
        return ZoneTrust(untrusted=values["untrusted"], trusted=values["trusted"])
    except ValueError as exc:
        raise ValueError(f"Invalid zone trust JSON: {exc}") from exc


def load_zone_trust(path: str | Path) -> ZoneTrust:
    """Load zone trust classifications from a UTF-8 JSON file."""
    try:
        content = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Could not read zone trust file: {exc}") from exc
    return parse_zone_trust_json(content)


def _network_set_covers(
    covering: tuple[IPAddressNetwork, ...],
    covered: tuple[IPAddressNetwork, ...],
) -> bool:
    """Return whether a union of networks contains every target network."""
    if len(covering) == 1:
        return all(
            target.version == covering[0].version and target.subnet_of(covering[0])
            for target in covered
        )
    for target in covered:
        _, target_start, target_end = _network_bounds(target)
        intervals = sorted(
            (
                start,
                end,
            )
            for network in covering
            for version, start, end in (_network_bounds(network),)
            if version == target.version
            and start <= target_end
            and end >= target_start
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


def find_shadowing_rules(
    rule: Rule,
    earlier_rules: Iterable[Rule],
) -> tuple[Rule, ...]:
    """Return earlier rules that soundly cover the rule's full match space."""
    eligible = [
        previous
        for previous in earlier_rules
        if (
            previous.src_zone.casefold() == rule.src_zone.casefold()
            and previous.dst_zone.casefold() == rule.dst_zone.casefold()
            and _service_covers(previous.service, rule.service)
        )
    ]
    single_cover = next(
        (previous for previous in eligible if _rule_covers(previous, rule)),
        None,
    )
    if single_cover is not None:
        return (single_cover,)

    # Requiring a shared source or destination rectangle avoids inventing
    # cross-product pairs by independently unioning both address dimensions.
    same_destination = [
        previous
        for previous in eligible
        if _network_set_covers(previous.dst_networks, rule.dst_networks)
    ]
    covering_sources = tuple(
        network for previous in same_destination for network in previous.src_networks
    )
    if same_destination and _network_set_covers(covering_sources, rule.src_networks):
        return tuple(same_destination)

    same_source = [
        previous
        for previous in eligible
        if _network_set_covers(previous.src_networks, rule.src_networks)
    ]
    covering_destinations = tuple(
        network for previous in same_source for network in previous.dst_networks
    )
    if same_source and _network_set_covers(covering_destinations, rule.dst_networks):
        return tuple(same_source)
    return ()


def _match_key(rule: Rule) -> tuple[object, ...]:
    """Build a hashable key for duplicate rule matching."""
    return (
        rule.src_zone.casefold(),
        rule.dst_zone.casefold(),
        rule.src_networks,
        rule.dst_networks,
        rule.service,
        rule.action,
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
    zone_trust: ZoneTrust | None = None,
    *,
    untrusted_zones: Iterable[str] = DEFAULT_UNTRUSTED_ZONES,
    trusted_zones: Iterable[str] = DEFAULT_TRUSTED_ZONES,
) -> list[Finding]:
    """Find risky and redundant rules in their original first-match order.

    Shadowing is reported when earlier rules on the same zone pair completely
    cover a later rule's addresses and service. Zone classification uses the
    supplied sets; the defaults are conventional demo names and should be
    customized for real environments.
    """
    ordered_rules = list(rules)
    trust = zone_trust or ZoneTrust(
        frozenset(untrusted_zones),
        frozenset(trusted_zones),
    )
    untrusted = trust.untrusted
    trusted = trust.trusted
    findings: list[Finding] = []
    first_by_match: dict[tuple[object, ...], Rule] = {}

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

        match_key = _match_key(rule)
        prior_match = first_by_match.get(match_key)
        first_by_match.setdefault(match_key, rule)
        if prior_match is not None:
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
                    related_rule_ids=(prior_match.id,),
                )
            )
            continue

        covering_rules = find_shadowing_rules(rule, ordered_rules[:index])
        if covering_rules:
            related_rule_ids = tuple(previous.id for previous in covering_rules)
            if len(covering_rules) == 1:
                explanation = (
                    f"Earlier rule {related_rule_ids[0]} matches all traffic "
                    "covered by this rule, so this rule is never reached."
                )
            else:
                explanation = (
                    f"Rule {rule.id} is shadowed by earlier rules "
                    f"{', '.join(related_rule_ids)} together."
                )
            findings.append(
                Finding(
                    rule_id=rule.id,
                    problem_type=ProblemType.SHADOWED,
                    severity=Severity.MEDIUM,
                    explanation=explanation,
                    suggested_fix=(
                        "Review the earlier rule and intended policy; remove the "
                        "unreachable rule or narrow/reorder rules with care."
                    ),
                    related_rule_ids=related_rule_ids,
                )
            )
    return findings
