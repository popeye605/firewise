"""Tests for per-zone genetic optimization and packet-based verification."""

import ipaddress

import pytest

from ai.genetic import (
    Packet,
    generate_boundary_packets,
    optimize_rules,
    verify_behavior_equivalence,
)
from core.models import Action, PortRange
from tests.helpers import make_rule


def test_boundary_packet_generator_includes_address_and_service_edges() -> None:
    rule = make_rule(
        "bounded",
        src_ip="10.0.0.0/24",
        dst_ip="192.0.2.0/24",
        protocol="tcp",
        ports=(PortRange(100, 200),),
    )

    packets = generate_boundary_packets([rule])

    assert packets
    assert any(packet.src_ip == ipaddress.ip_address("10.0.0.0") for packet in packets)
    assert any(packet.src_ip == ipaddress.ip_address("10.0.0.255") for packet in packets)
    assert any(packet.dst_ip == ipaddress.ip_address("192.0.2.0") for packet in packets)
    assert {packet.dst_port for packet in packets} >= {99, 100, 200, 201}


def test_verifier_includes_boundaries_and_exact_random_count() -> None:
    rules = [make_rule("allow", src_ip="10.0.0.0/24")]
    result = verify_behavior_equivalence(rules, rules, random_packet_count=1000, seed=7)

    assert result.equivalent
    assert result.random_packets_tested == 1000
    assert result.boundary_packets_tested > 0
    assert result.packets_tested == result.boundary_packets_tested + 1000
    assert result.mismatch_count == 0


def test_verifier_detects_changed_allow_decision() -> None:
    original = [make_rule("allow", src_ip="10.0.0.0/24")]
    candidate = []

    result = verify_behavior_equivalence(
        original,
        candidate,
        random_packet_count=0,
    )

    assert not result.equivalent
    assert result.mismatch_count > 0
    assert result.mismatches[0].before_allowed
    assert not result.mismatches[0].after_allowed


def test_optimizer_removes_duplicate_rules_and_preserves_behavior() -> None:
    rules = [
        make_rule("first", src_zone="Build", dst_zone="Artifact"),
        make_rule("copy-1", src_zone="Build", dst_zone="Artifact"),
        make_rule("copy-2", src_zone="Build", dst_zone="Artifact"),
        make_rule("independent", src_zone="LAN", dst_zone="WAN"),
    ]

    result = optimize_rules(
        rules,
        population_size=12,
        generations=12,
        random_packet_count=1000,
        seed=17,
    )

    assert result.before_rule_count == 4
    assert result.after_rule_count < result.before_rule_count
    assert result.reduction_percent > 0
    assert result.verification.equivalent
    assert result.verification.random_packets_tested == 1000
    assert result.verification.boundary_packets_tested > 0
    assert (
        result.verification.packets_tested
        == result.verification.boundary_packets_tested + 1000
    )
    assert len(result.fitness_history) == 13
    assert all(
        later >= earlier
        for earlier, later in zip(
            result.fitness_history,
            result.fitness_history[1:],
            strict=False,
        )
    )


def test_optimizer_runs_per_zone_pair_without_cross_pair_reordering() -> None:
    rules = [
        make_rule("a1", src_zone="A", dst_zone="B"),
        make_rule("a2", src_zone="A", dst_zone="B"),
        make_rule("c1", src_zone="C", dst_zone="D"),
        make_rule("c2", src_zone="C", dst_zone="D"),
    ]

    result = optimize_rules(
        rules,
        population_size=8,
        generations=5,
        random_packet_count=50,
    )

    pairs = {
        (rule.src_zone.casefold(), rule.dst_zone.casefold())
        for rule in result.recommended_rules
    }
    assert pairs == {("a", "b"), ("c", "d")}
    assert result.optimized_zone_pairs == (("a", "b"), ("c", "d"))
    assert result.verification.equivalent


def test_optimizer_rejects_unsupported_rules_instead_of_guessing() -> None:
    rule = make_rule("unsupported")
    unsupported = type(rule)(
        id=rule.id,
        src_zone=rule.src_zone,
        dst_zone=rule.dst_zone,
        src_networks=rule.src_networks,
        dst_networks=rule.dst_networks,
        service=rule.service,
        action=rule.action,
        log=rule.log,
        not_analyzed=("schedule",),
    )

    with pytest.raises(ValueError, match="not-analyzed features"):
        optimize_rules([unsupported])


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"population_size": 3}, "at least 4"),
        ({"generations": 0}, "at least 1"),
        ({"mutation_rate": 1.1}, "between 0 and 1"),
        ({"random_packet_count": -1}, "random_packet_count"),
    ],
)
def test_optimizer_rejects_invalid_parameters(options: dict, message: str) -> None:
    rules = [make_rule("first"), make_rule("second")]
    with pytest.raises(ValueError, match=message):
        optimize_rules(rules, **options)


def test_optimizer_never_changes_behavior_when_candidate_is_rejected() -> None:
    rules = [
        make_rule("allow", src_zone="A", dst_zone="B"),
        make_rule("deny", src_zone="A", dst_zone="B", action=Action.DENY),
    ]

    result = optimize_rules(
        rules,
        population_size=8,
        generations=5,
        random_packet_count=1000,
    )

    assert result.verification.equivalent
    assert result.recommended_rules == result.original_rules or not result.candidate_rejected
