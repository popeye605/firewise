"""Tests for the bundled path and optimizer example policies."""

from pathlib import Path

from ai.astar import astar_search, breadth_first_search, build_zone_graph
from ai.genetic import optimize_rules
from core.loader import load_rules

ROOT = Path(__file__).resolve().parents[1]


def test_astar_sample_produces_different_astar_and_bfs_paths() -> None:
    rules = load_rules(ROOT / "data" / "astar_demo.csv")

    astar_result = astar_search(build_zone_graph(rules), "Alpha", "Delta")
    bfs_result = breadth_first_search(build_zone_graph(rules), "Alpha", "Delta")

    assert astar_result.rule_ids == ("X2", "X3", "X4")
    assert bfs_result.rule_ids == ("X1",)
    assert len(astar_result.path) > len(bfs_result.path)


def test_stress_sample_has_non_flat_optimizer_fitness_and_reduces_rules() -> None:
    rules = load_rules(ROOT / "data" / "stress_rules.csv")

    result = optimize_rules(
        rules,
        population_size=12,
        generations=12,
        random_packet_count=100,
        seed=2026,
    )

    assert len(rules) == 21
    assert result.after_rule_count < result.before_rule_count
    assert max(result.fitness_history) > result.fitness_history[0]
    assert result.verification.equivalent
