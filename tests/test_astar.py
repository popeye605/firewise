"""Tests for A* and BFS on firewall zone graphs."""

import math

import pytest

from ai.astar import (
    astar_search,
    breadth_first_search,
    build_zone_graph,
    permit_risk,
    risk_cost,
)
from core.loader import load_demo_rules
from core.models import Action
from tests.helpers import make_rule


def test_graph_contains_only_permit_rules_with_risk_costs() -> None:
    permit = make_rule("allow", src_zone="Internet", dst_zone="Web", log=False)
    deny = make_rule("deny", src_zone="Web", dst_zone="Database", action=Action.DENY)

    graph = build_zone_graph([permit, deny])

    assert graph.number_of_edges() == 1
    assert graph["Internet"]["Web"]["allow"]["rule_id"] == "allow"
    assert graph["Internet"]["Web"]["allow"]["cost"] == risk_cost(permit)
    assert risk_cost(permit) > 0


def test_riskier_permit_has_lower_cost() -> None:
    ordinary = make_rule("ordinary")
    broad_unlogged = make_rule(
        "risky",
        src_zone="Internet",
        dst_zone="Database",
        src_ip="any",
        dst_ip="any",
        protocol="any",
        ports=(),
        log=False,
    )

    assert permit_risk(broad_unlogged) > permit_risk(ordinary)
    assert risk_cost(broad_unlogged) < risk_cost(ordinary)


def test_astar_chooses_lower_risk_cost_path_while_bfs_chooses_fewer_hops() -> None:
    rules = [
        make_rule("direct", src_zone="Internet", dst_zone="Database"),
        make_rule(
            "risky-one",
            src_zone="Internet",
            dst_zone="Web",
            src_ip="any",
            dst_ip="any",
            protocol="any",
            ports=(),
            log=False,
        ),
        make_rule(
            "risky-two",
            src_zone="Web",
            dst_zone="Database",
            src_ip="any",
            dst_ip="any",
            protocol="any",
            ports=(),
            log=False,
        ),
    ]
    graph = build_zone_graph(rules)

    astar = astar_search(graph, "Internet", "Database")
    bfs = breadth_first_search(graph, "Internet", "Database")

    assert astar.path == ("Internet", "Web", "Database")
    assert astar.rule_ids == ("risky-one", "risky-two")
    assert astar.total_cost < bfs.total_cost
    assert bfs.path == ("Internet", "Database")
    assert bfs.nodes_explored >= 1


def test_searches_return_path_and_exploration_counts_on_demo() -> None:
    graph = build_zone_graph(load_demo_rules())

    astar = astar_search(graph, "Internet", "Database")
    bfs = breadth_first_search(graph, "Internet", "Database")

    assert astar.found
    assert bfs.found
    assert astar.path[0] == bfs.path[0] == "Internet"
    assert astar.path[-1] == bfs.path[-1] == "Database"
    assert astar.nodes_explored > 0
    assert bfs.nodes_explored > 0
    assert len(astar.rule_ids) == len(astar.path) - 1


def test_no_route_returns_empty_path_and_infinite_cost() -> None:
    graph = build_zone_graph(
        [make_rule("isolated", src_zone="LAN", dst_zone="WAN")]
    )

    for search in (astar_search, breadth_first_search):
        result = search(graph, "LAN", "WAN")
        assert result.found
        assert result.path == ("LAN", "WAN")

    graph.add_node("Database")
    for search in (astar_search, breadth_first_search):
        result = search(graph, "LAN", "Database")
        assert not result.found
        assert result.path == ()
        assert math.isinf(result.total_cost)


def test_same_source_and_target_is_zero_cost_path() -> None:
    graph = build_zone_graph([make_rule("edge", src_zone="LAN", dst_zone="WAN")])

    for search in (astar_search, breadth_first_search):
        result = search(graph, "LAN", "LAN")
        assert result.path == ("LAN",)
        assert result.rule_ids == ()
        assert result.total_cost == 0
        assert result.nodes_explored == 1


def test_unknown_zone_raises_clear_error() -> None:
    graph = build_zone_graph([make_rule("edge", src_zone="LAN", dst_zone="WAN")])

    with pytest.raises(ValueError, match="Unknown zone"):
        astar_search(graph, "LAN", "missing")
    with pytest.raises(ValueError, match="Unknown zone"):
        breadth_first_search(graph, "missing", "WAN")


def test_parallel_rules_select_lowest_cost_rule() -> None:
    regular = make_rule("regular", src_zone="LAN", dst_zone="WAN")
    risky = make_rule(
        "risky",
        src_zone="LAN",
        dst_zone="WAN",
        src_ip="any",
        dst_ip="any",
        protocol="any",
        ports=(),
        log=False,
    )
    graph = build_zone_graph([regular, risky])

    result = astar_search(graph, "LAN", "WAN")

    assert result.rule_ids == ("risky",)
