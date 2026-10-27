"""Per-zone-pair genetic rule optimization and behavior verification."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from itertools import chain
import random
from typing import Callable, Sequence

from ai.astar import permit_risk
from core.checks import ZoneTrust
from core.models import Action, IPAddressNetwork, Rule

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
ZonePair = tuple[str, str]
Chromosome = tuple[str, ...]

_ANY_PROTOCOLS = ("tcp", "udp", "icmp", "icmpv6")
_COMMON_PORTS = (0, 1, 22, 53, 80, 123, 443, 3389, 65535)
_LARGE_GROUP_RULE_LIMIT = 200
_LARGE_POLICY_PACKET_CAP = 100
_LARGE_POLICY_POPULATION_CAP = 8
_LARGE_POLICY_GENERATION_CAP = 6


@dataclass(frozen=True, slots=True)
class Packet:
    """A synthetic packet used to compare first-match policy decisions."""

    src_zone: str
    dst_zone: str
    src_ip: IPAddress
    dst_ip: IPAddress
    protocol: str
    dst_port: int | None


@dataclass(frozen=True, slots=True)
class PacketMismatch:
    """A test packet whose allowed/blocked decision changed."""

    packet: Packet
    before_allowed: bool
    after_allowed: bool


@dataclass(frozen=True, slots=True)
class BehaviorVerification:
    """Boundary and random packet comparison outcome."""

    equivalent: bool
    packets_tested: int
    boundary_packets_tested: int
    random_packets_tested: int
    mismatch_count: int
    mismatches: tuple[PacketMismatch, ...]


@dataclass(frozen=True, slots=True)
class OptimizationResult:
    """Review-only optimized policy with its verification evidence."""

    original_rules: tuple[Rule, ...]
    recommended_rules: tuple[Rule, ...]
    before_rule_count: int
    after_rule_count: int
    before_risk_score: int
    after_risk_score: int
    reduction_percent: float
    fitness_history: tuple[float, ...]
    verification: BehaviorVerification
    candidate_rejected: bool
    optimized_zone_pairs: tuple[ZonePair, ...]
    removed_deny_rules: tuple[str, ...] = ()
    packet_count_cap: int | None = None
    search_population_cap: int | None = None
    search_generation_cap: int | None = None


def _address_samples(network: IPAddressNetwork) -> set[IPAddress]:
    """Get address boundaries, adjacent addresses, and an interior sample."""
    start = int(network.network_address)
    end = int(network.broadcast_address)
    maximum = (1 << network.max_prefixlen) - 1
    values = {start, end, (start + end) // 2}
    if start > 0:
        values.add(start - 1)
    if end < maximum:
        values.add(end + 1)
    return {ipaddress.ip_address(value) for value in values}


def _ports_for_rule(rule: Rule, protocol: str) -> tuple[int | None, ...]:
    """Choose service boundary ports or representative non-port values."""
    service = rule.service
    if protocol not in {"tcp", "udp"}:
        return (None,)
    if service.protocol == "any" or not service.ports:
        return _COMMON_PORTS

    ports: set[int] = set()
    for port_range in service.ports:
        for port in (port_range.start - 1, port_range.start, port_range.end, port_range.end + 1):
            if 0 <= port <= 65535:
                ports.add(port)
    return tuple(sorted(ports))


def generate_boundary_packets(
    rules: Sequence[Rule],
    max_packets: int | None = None,
) -> tuple[Packet, ...]:
    """Generate deterministic packets from each rule's address and service boundaries."""
    if max_packets is not None and max_packets < 1:
        raise ValueError("max_packets must be positive.")

    def packet_key(packet: Packet) -> tuple[str, str, int, int, int, str, int]:
        return (
            packet.src_zone.casefold(),
            packet.dst_zone.casefold(),
            packet.src_ip.version,
            int(packet.src_ip),
            int(packet.dst_ip),
            packet.protocol,
            -1 if packet.dst_port is None else packet.dst_port,
        )

    packets: set[Packet] = set()
    for rule in rules:
        protocols = (
            _ANY_PROTOCOLS
            if rule.service.protocol == "any"
            else (rule.service.protocol,)
        )
        for source_network in rule.src_networks:
            source_samples = _address_samples(source_network)
            for destination_network in rule.dst_networks:
                if source_network.version != destination_network.version:
                    continue
                destination_samples = _address_samples(destination_network)
                for protocol in protocols:
                    for port in _ports_for_rule(rule, protocol):
                        for source_ip in source_samples:
                            for destination_ip in destination_samples:
                                packets.add(
                                    Packet(
                                        src_zone=rule.src_zone,
                                        dst_zone=rule.dst_zone,
                                        src_ip=source_ip,
                                        dst_ip=destination_ip,
                                        protocol=protocol,
                                        dst_port=port,
                                    )
                                )
                                if max_packets is not None and len(packets) >= max_packets:
                                    return tuple(sorted(packets, key=packet_key))
    return tuple(sorted(packets, key=packet_key))


def _random_address(network: IPAddressNetwork, rng: random.Random) -> IPAddress:
    """Choose an address uniformly from the inclusive network interval."""
    start = int(network.network_address)
    end = int(network.broadcast_address)
    return ipaddress.ip_address(rng.randint(start, end))


def _random_packet(rules: Sequence[Rule], rng: random.Random) -> Packet:
    """Generate a packet based on one rule's zones, address families, and service."""
    rule = rng.choice(rules)
    compatible_pairs = [
        (source, destination)
        for source in rule.src_networks
        for destination in rule.dst_networks
        if source.version == destination.version
    ]
    if not compatible_pairs:
        raise ValueError(f"Rule {rule.id} has no same-family source/destination networks.")
    source_network, destination_network = rng.choice(compatible_pairs)

    if rule.service.protocol == "any":
        protocol = rng.choice(_ANY_PROTOCOLS)
    else:
        protocol = rule.service.protocol
    if protocol in {"tcp", "udp"}:
        if rule.service.ports:
            port_range = rng.choice(rule.service.ports)
            dst_port = rng.randint(port_range.start, port_range.end)
        else:
            dst_port = rng.randint(0, 65535)
    else:
        dst_port = None
    return Packet(
        src_zone=rule.src_zone,
        dst_zone=rule.dst_zone,
        src_ip=_random_address(source_network, rng),
        dst_ip=_random_address(destination_network, rng),
        protocol=protocol,
        dst_port=dst_port,
    )


def _matches(rule: Rule, packet: Packet) -> bool:
    """Evaluate a single normalized rule against a synthetic packet."""
    if (
        rule.src_zone.casefold() != packet.src_zone.casefold()
        or rule.dst_zone.casefold() != packet.dst_zone.casefold()
        or not any(
            packet.src_ip.version == network.version and packet.src_ip in network
            for network in rule.src_networks
        )
        or not any(
            packet.dst_ip.version == network.version and packet.dst_ip in network
            for network in rule.dst_networks
        )
    ):
        return False
    service = rule.service
    if service.protocol != "any" and service.protocol != packet.protocol:
        return False
    if service.protocol == "any" or not service.ports:
        return True
    return packet.dst_port is not None and any(
        port_range.start <= packet.dst_port <= port_range.end
        for port_range in service.ports
    )


def _allows(rules: Sequence[Rule], packet: Packet) -> bool:
    """Return the first-match allow decision; implicit deny is false."""
    for rule in rules:
        if _matches(rule, packet):
            return rule.action is Action.PERMIT
    return False


def _validate_rules(rules: Sequence[Rule]) -> None:
    """Reject duplicate identifiers and rules with unsupported semantics."""
    rule_ids = [rule.id for rule in rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("Rule IDs must be unique for genetic optimization.")
    unsupported = [
        rule.id
        for rule in rules
        if rule.not_analyzed
    ]
    if unsupported:
        raise ValueError(
            "Cannot optimize rules with unsupported, not-analyzed features: "
            + ", ".join(unsupported)
        )


def _group_rules(rules: Sequence[Rule]) -> dict[ZonePair, list[Rule]]:
    """Group rules by case-insensitive source/destination zone pair."""
    groups: dict[ZonePair, list[Rule]] = defaultdict(list)
    for rule in rules:
        groups[(rule.src_zone.casefold(), rule.dst_zone.casefold())].append(rule)
    return dict(groups)


def _candidate_rules(chromosome: Chromosome, by_id: dict[str, Rule]) -> tuple[Rule, ...]:
    """Materialize an ordered chromosome as rules."""
    return tuple(by_id[rule_id] for rule_id in chromosome)


def _risk_score(
    rules: Sequence[Rule],
    zone_trust: ZoneTrust | None = None,
) -> int:
    """Sum risk points for broad, unlogged, and trust-boundary permits."""
    return sum(
        permit_risk(rule, zone_trust)
        for rule in rules
        if rule.action is Action.PERMIT
    )


def _decisions(rules: Sequence[Rule], packets: Sequence[Packet]) -> tuple[bool, ...]:
    """Evaluate policy decisions for a fixed packet corpus."""
    return tuple(_allows(rules, packet) for packet in packets)


def verify_behavior_equivalence(
    original_rules: Sequence[Rule],
    candidate_rules: Sequence[Rule],
    *,
    random_packet_count: int = 1000,
    seed: int = 2026,
    boundary_packet_limit: int | None = None,
) -> BehaviorVerification:
    """Compare allow/deny decisions on rule boundaries and seeded random packets."""
    if random_packet_count < 0:
        raise ValueError("random_packet_count cannot be negative.")
    _validate_rules(original_rules)
    _validate_rules(candidate_rules)

    original_groups = _group_rules(original_rules)
    candidate_pairs = set(_group_rules(candidate_rules))
    if not candidate_pairs.issubset(original_groups):
        raise ValueError("Candidate contains a zone pair absent from the original policy.")
    boundary_packets = generate_boundary_packets(original_rules, boundary_packet_limit)
    boundary_count = len(boundary_packets)
    rng = random.Random(seed)
    if random_packet_count and not original_rules:
        raise ValueError("Cannot generate random packets for an empty policy.")
    random_packets = [
        _random_packet(original_rules, rng)
        for _ in range(random_packet_count)
    ]

    mismatches: list[PacketMismatch] = []
    mismatch_count = 0
    for packet in chain(boundary_packets, random_packets):
        before = _allows(original_rules, packet)
        after = _allows(candidate_rules, packet)
        if before != after:
            mismatch_count += 1
            if len(mismatches) < 20:
                mismatches.append(PacketMismatch(packet, before, after))
    return BehaviorVerification(
        equivalent=mismatch_count == 0,
        packets_tested=boundary_count + len(random_packets),
        boundary_packets_tested=boundary_count,
        random_packets_tested=random_packet_count,
        mismatch_count=mismatch_count,
        mismatches=tuple(mismatches),
    )


def _group_boundary_packets(
    group: Sequence[Rule],
    max_packets: int | None = None,
) -> tuple[Packet, ...]:
    """Create the fixed training corpus for one zone-pair chromosome."""
    return generate_boundary_packets(group, max_packets)


def _fitness(
    chromosome: Chromosome,
    original_decisions: tuple[bool, ...],
    packets: Sequence[Packet],
    by_id: dict[str, Rule],
    zone_trust: ZoneTrust | None = None,
) -> float:
    """Maximize compactness and lower risk while heavily penalizing behavior changes."""
    candidate = _candidate_rules(chromosome, by_id)
    mismatches = sum(
        before != _allows(candidate, packet)
        for before, packet in zip(original_decisions, packets, strict=True)
    )
    return (
        -10.0 * len(candidate)
        - float(_risk_score(candidate, zone_trust))
        - 100_000.0 * mismatches
    )


def _select(
    population: Sequence[Chromosome],
    fitnesses: Sequence[float],
    rng: random.Random,
) -> Chromosome:
    """Choose a parent with small tournament selection."""
    candidates = rng.sample(range(len(population)), k=min(3, len(population)))
    winner = max(candidates, key=lambda index: fitnesses[index])
    return population[winner]


def _crossover(
    first: Chromosome,
    second: Chromosome,
    all_ids: tuple[str, ...],
    rng: random.Random,
    required_ids: frozenset[str] = frozenset(),
) -> Chromosome:
    """Combine parent membership choices and inherit order from both parents."""
    first_set = set(first)
    second_set = set(second)
    selected = {
        rule_id
        for rule_id in all_ids
        if (
            rule_id in first_set and rule_id in second_set
            or rule_id in first_set
            and rule_id not in second_set
            and rng.random() < 0.5
            or rule_id not in first_set
            and rule_id in second_set
            and rng.random() < 0.5
        )
    }
    selected.update(required_ids)
    order_sources = (first, second) if rng.random() < 0.5 else (second, first)
    child: list[str] = []
    for parent in order_sources:
        child.extend(rule_id for rule_id in parent if rule_id in selected and rule_id not in child)
    child.extend(rule_id for rule_id in all_ids if rule_id in selected and rule_id not in child)
    return tuple(child)


def _mutate(
    chromosome: Chromosome,
    all_ids: tuple[str, ...],
    rng: random.Random,
    required_ids: frozenset[str] = frozenset(),
) -> Chromosome:
    """Remove, restore, or swap a rule to explore the search space."""
    genes = list(chromosome)
    genes.extend(
        rule_id
        for rule_id in all_ids
        if rule_id in required_ids and rule_id not in genes
    )
    operations = ["remove", "add", "swap"]
    removable_indices = [
        index for index, rule_id in enumerate(genes) if rule_id not in required_ids
    ]
    if not removable_indices:
        operations.remove("remove")
    if len(genes) < 2:
        operations.remove("swap")
    if len(genes) == len(all_ids):
        operations.remove("add")
    if not operations:
        return tuple(genes)

    operation = rng.choice(operations)
    if operation == "remove":
        genes.pop(rng.choice(removable_indices))
    elif operation == "add":
        missing = [rule_id for rule_id in all_ids if rule_id not in genes]
        if missing:
            genes.insert(rng.randrange(len(genes) + 1), rng.choice(missing))
    elif len(genes) > 1:
        first_index, second_index = rng.sample(range(len(genes)), 2)
        genes[first_index], genes[second_index] = genes[second_index], genes[first_index]
    return tuple(genes)


def _optimize_group(
    rules: Sequence[Rule],
    *,
    population_size: int,
    generations: int,
    mutation_rate: float,
    rng: random.Random,
    required_ids: frozenset[str] = frozenset(),
    zone_trust: ZoneTrust | None = None,
    max_boundary_packets: int | None = None,
    progress_callback: Callable[[float], None] | None = None,
) -> tuple[tuple[Rule, ...], tuple[float, ...]]:
    """Evolve one zone pair's keep/order chromosome."""
    all_ids = tuple(rule.id for rule in rules)
    by_id = {rule.id: rule for rule in rules}
    packets = _group_boundary_packets(rules, max_boundary_packets)
    original_decisions = _decisions(rules, packets)
    population: list[Chromosome] = [all_ids]
    while len(population) < population_size:
        genes = [
            rule_id
            for rule_id in all_ids
            if rule_id in required_ids or rng.random() < rng.uniform(0.5, 1.0)
        ]
        rng.shuffle(genes)
        population.append(tuple(genes))

    fitnesses = [
        _fitness(chromosome, original_decisions, packets, by_id, zone_trust)
        for chromosome in population
    ]
    history = [max(fitnesses)]
    for generation in range(1, generations + 1):
        elite_index = max(range(len(population)), key=lambda index: fitnesses[index])
        next_population = [population[elite_index]]
        while len(next_population) < population_size:
            parent_a = _select(population, fitnesses, rng)
            parent_b = _select(population, fitnesses, rng)
            child = _crossover(parent_a, parent_b, all_ids, rng, required_ids)
            if rng.random() < mutation_rate:
                child = _mutate(child, all_ids, rng, required_ids)
            next_population.append(child)
        population = next_population
        fitnesses = [
            _fitness(chromosome, original_decisions, packets, by_id, zone_trust)
            for chromosome in population
        ]
        history.append(max(fitnesses))
        if progress_callback is not None:
            progress_callback(generation / generations)

    best = max(range(len(population)), key=lambda index: fitnesses[index])
    return _candidate_rules(population[best], by_id), tuple(history)


def optimize_rules(
    rules: Sequence[Rule],
    *,
    population_size: int = 24,
    generations: int = 30,
    mutation_rate: float = 0.15,
    random_packet_count: int = 1000,
    seed: int = 2026,
    progress_callback: Callable[[float], None] | None = None,
    keep_deny_rules: bool = False,
    keep_logged_rules: bool = True,
    zone_trust: ZoneTrust | None = None,
) -> OptimizationResult:
    """Recommend compact per-zone-pair rule lists and verify behavior.

    Genetic search is performed independently for each zone pair. Unsupported
    rule semantics are refused rather than approximated. The candidate is tested
    against boundary-derived and random packets; if any decision changes, the
    recommendation is rolled back to the original list.
    """
    if not rules:
        raise ValueError("Cannot optimize an empty rule list.")
    if population_size < 4:
        raise ValueError("population_size must be at least 4.")
    if generations < 1:
        raise ValueError("generations must be at least 1.")
    if not 0 <= mutation_rate <= 1:
        raise ValueError("mutation_rate must be between 0 and 1.")
    if random_packet_count < 0:
        raise ValueError("random_packet_count cannot be negative.")
    _validate_rules(rules)

    original = tuple(rules)
    groups = _group_rules(original)
    pair_indices: dict[ZonePair, int] = {}
    for index, rule in enumerate(original):
        pair_indices.setdefault((rule.src_zone.casefold(), rule.dst_zone.casefold()), index)
    recommendations: list[tuple[ZonePair, tuple[Rule, ...]]] = []
    group_histories: list[tuple[float, ...]] = []
    optimized_pairs: list[ZonePair] = []
    ordered_groups = sorted(groups.items(), key=lambda item: pair_indices[item[0]])
    group_count = len(ordered_groups)
    large_group = any(
        len(group) > _LARGE_GROUP_RULE_LIMIT for group in groups.values()
    )
    boundary_packet_limit = (
        _LARGE_POLICY_PACKET_CAP // 2 if large_group else None
    )
    effective_random_packet_count = (
        min(random_packet_count, _LARGE_POLICY_PACKET_CAP // 2)
        if large_group
        else random_packet_count
    )
    for group_index, (pair, group) in enumerate(ordered_groups):
        if len(group) < 2:
            recommendations.append((pair, tuple(group)))
            if progress_callback is not None:
                progress_callback((group_index + 1) / group_count)
            continue
        group_rng = random.Random(seed + pair_indices[pair])

        def report_group_progress(progress: float) -> None:
            if progress_callback is not None:
                progress_callback((group_index + progress) / group_count)

        optimized_group, history = _optimize_group(
            group,
            population_size=(
                min(population_size, _LARGE_POLICY_POPULATION_CAP)
                if len(group) > _LARGE_GROUP_RULE_LIMIT
                else population_size
            ),
            generations=(
                min(generations, _LARGE_POLICY_GENERATION_CAP)
                if len(group) > _LARGE_GROUP_RULE_LIMIT
                else generations
            ),
            mutation_rate=mutation_rate,
            rng=group_rng,
            required_ids=frozenset(
                rule.id
                for rule in group
                if rule.action is Action.DENY
                and (keep_deny_rules or (keep_logged_rules and rule.log))
            ),
            zone_trust=zone_trust,
            max_boundary_packets=(
                boundary_packet_limit
                if len(group) > _LARGE_GROUP_RULE_LIMIT
                else None
            ),
            progress_callback=report_group_progress,
        )
        recommendations.append((pair, optimized_group))
        group_histories.append(history)
        optimized_pairs.append(pair)
        if progress_callback is not None:
            progress_callback((group_index + 1) / group_count)

    recommended = tuple(
        rule
        for _, group_recommendation in recommendations
        for rule in group_recommendation
    )
    maximum_generations = max((len(history) for history in group_histories), default=0)
    fitness_history = tuple(
        sum(
            history[generation]
            for history in group_histories
            if generation < len(history)
        )
        for generation in range(maximum_generations)
    )
    verification = verify_behavior_equivalence(
        original,
        recommended,
        random_packet_count=effective_random_packet_count,
        seed=seed,
        boundary_packet_limit=boundary_packet_limit,
    )
    candidate_rejected = not verification.equivalent
    if candidate_rejected:
        recommended = original
        verification = verify_behavior_equivalence(
            original,
            recommended,
            random_packet_count=effective_random_packet_count,
            seed=seed,
            boundary_packet_limit=boundary_packet_limit,
        )

    before_count = len(original)
    after_count = len(recommended)
    recommended_ids = {rule.id for rule in recommended}
    reduction = 100.0 * (before_count - after_count) / before_count
    return OptimizationResult(
        original_rules=original,
        recommended_rules=recommended,
        before_rule_count=before_count,
        after_rule_count=after_count,
        before_risk_score=_risk_score(original, zone_trust),
        after_risk_score=_risk_score(recommended, zone_trust),
        reduction_percent=reduction,
        fitness_history=fitness_history,
        verification=verification,
        candidate_rejected=candidate_rejected,
        optimized_zone_pairs=tuple(optimized_pairs),
        removed_deny_rules=tuple(
            rule.id
            for rule in original
            if rule.action is Action.DENY
            and rule.id not in recommended_ids
        ),
        packet_count_cap=_LARGE_POLICY_PACKET_CAP if large_group else None,
        search_population_cap=(
            _LARGE_POLICY_POPULATION_CAP if large_group else None
        ),
        search_generation_cap=(
            _LARGE_POLICY_GENERATION_CAP if large_group else None
        ),
    )
