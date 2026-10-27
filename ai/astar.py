"""A* and breadth-first attack-path searches over firewall zones."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import heapq
import itertools
import math
from typing import Callable

import networkx as nx

from core.checks import (
    DEFAULT_TRUSTED_ZONES,
    DEFAULT_UNTRUSTED_ZONES,
    find_shadowing_rules,
)
from core.models import Rule


@dataclass(frozen=True, slots=True)
class PathSearchResult:
    """Path and work metrics produced by one search algorithm."""

    algorithm: str
    path: tuple[str, ...]
    rule_ids: tuple[str, ...]
    total_cost: float
    nodes_explored: int

    @property
    def found(self) -> bool:
        """Whether a route connects the requested source and target."""
        return bool(self.path)


def permit_risk(rule: Rule) -> int:
    """Give higher risk values to broad, unlogged, or trust-boundary permits."""
    if rule.action.value != "permit":
        raise ValueError(f"Rule {rule.id} is not a permit and cannot form an attack edge.")
    risk = 1
    if (
        all(str(network) in {"0.0.0.0/0", "::/0"} for network in rule.src_networks)
        and all(str(network) in {"0.0.0.0/0", "::/0"} for network in rule.dst_networks)
        and rule.service.protocol == "any"
    ):
        risk += 10
    if not rule.log:
        risk += 2
    if (
        rule.src_zone.casefold() in DEFAULT_UNTRUSTED_ZONES
        and rule.dst_zone.casefold() in DEFAULT_TRUSTED_ZONES
    ):
        risk += 5
    return risk


def risk_cost(rule: Rule) -> float:
    """Map permit risk to a positive cost; riskier rules cost less."""
    return 10.0 / (1 + permit_risk(rule))


def rule_is_reachable(rule: Rule, earlier_rules: list[Rule]) -> bool:
    """Return whether any traffic matching a rule can reach it in order."""
    return not find_shadowing_rules(rule, earlier_rules)


def build_zone_graph(
    rules: list[Rule],
    respect_order: bool = True,
) -> nx.MultiDiGraph:
    """Create a directed graph from permit rules reachable in policy order."""
    graph = nx.MultiDiGraph()
    earlier_rules: list[Rule] = []
    for rule in rules:
        if rule.action.value == "permit" and (
            not respect_order or rule_is_reachable(rule, earlier_rules)
        ):
            graph.add_edge(
                rule.src_zone,
                rule.dst_zone,
                key=rule.id,
                rule_id=rule.id,
                cost=risk_cost(rule),
                risk=permit_risk(rule),
            )
        earlier_rules.append(rule)
    return graph


def _best_edge(graph: nx.MultiDiGraph, source: str, target: str) -> tuple[str, float]:
    """Choose the lowest-cost permitted rule among parallel zone edges."""
    edges = graph.get_edge_data(source, target)
    if not edges:
        raise ValueError(f"No permit edge exists from {source!r} to {target!r}.")
    rule_id, data = min(
        edges.items(),
        key=lambda edge: (float(edge[1]["cost"]), str(edge[1]["rule_id"])),
    )
    return str(data.get("rule_id", rule_id)), float(data["cost"])


def _result(
    graph: nx.MultiDiGraph,
    algorithm: str,
    path: tuple[str, ...],
    nodes_explored: int,
) -> PathSearchResult:
    """Build route metrics from the selected sequence of zones."""
    if not path:
        return PathSearchResult(algorithm, (), (), math.inf, nodes_explored)
    rule_ids: list[str] = []
    total_cost = 0.0
    for source, target in itertools.pairwise(path):
        rule_id, cost = _best_edge(graph, source, target)
        rule_ids.append(rule_id)
        total_cost += cost
    return PathSearchResult(
        algorithm=algorithm,
        path=path,
        rule_ids=tuple(rule_ids),
        total_cost=total_cost,
        nodes_explored=nodes_explored,
    )


def _validate_endpoints(graph: nx.MultiDiGraph, source: str, target: str) -> None:
    """Reject missing zones before starting a search."""
    missing = [zone for zone in (source, target) if zone not in graph]
    if missing:
        raise ValueError("Unknown zone(s): " + ", ".join(missing))


def astar_search(
    graph: nx.MultiDiGraph,
    source: str,
    target: str,
) -> PathSearchResult:
    """Find the minimum-risk-cost route with an explicit A* implementation.

    The heuristic is the minimum possible edge cost multiplied by the minimum
    number of remaining hops. It is admissible because every edge costs at least
    that minimum; therefore A* returns a minimum-cost route.
    """
    _validate_endpoints(graph, source, target)
    if source == target:
        return _result(graph, "A*", (source,), 1)

    edge_costs = [float(data["cost"]) for _, _, data in graph.edges(data=True)]
    minimum_cost = min(edge_costs, default=0.0)
    heuristic_cache: dict[str, float] = {}

    def heuristic(zone: str) -> float:
        if zone not in heuristic_cache:
            try:
                hops = nx.shortest_path_length(graph, zone, target)
            except nx.NetworkXNoPath:
                heuristic_cache[zone] = math.inf
            else:
                heuristic_cache[zone] = hops * minimum_cost
        return heuristic_cache[zone]

    frontier: list[tuple[float, float, int, str]] = []
    order = itertools.count()
    heapq.heappush(frontier, (heuristic(source), 0.0, next(order), source))
    best_cost = {source: 0.0}
    parent: dict[str, str] = {}
    explored: set[str] = set()

    while frontier:
        _, path_cost, _, zone = heapq.heappop(frontier)
        if zone in explored or path_cost > best_cost.get(zone, math.inf):
            continue
        explored.add(zone)
        if zone == target:
            path = _reconstruct_path(parent, source, target)
            return _result(graph, "A*", path, len(explored))

        for neighbor in graph.successors(zone):
            _, edge_cost = _best_edge(graph, zone, neighbor)
            candidate = path_cost + edge_cost
            if candidate < best_cost.get(neighbor, math.inf):
                best_cost[neighbor] = candidate
                parent[neighbor] = zone
                heapq.heappush(
                    frontier,
                    (candidate + heuristic(neighbor), candidate, next(order), neighbor),
                )

    return _result(graph, "A*", (), len(explored))


def breadth_first_search(
    graph: nx.MultiDiGraph,
    source: str,
    target: str,
) -> PathSearchResult:
    """Find a route with fewest zone hops using an explicit BFS implementation."""
    _validate_endpoints(graph, source, target)
    if source == target:
        return _result(graph, "BFS", (source,), 1)

    frontier = deque([source])
    parent: dict[str, str] = {}
    visited = {source}
    explored = 0

    while frontier:
        zone = frontier.popleft()
        explored += 1
        if zone == target:
            return _result(
                graph,
                "BFS",
                _reconstruct_path(parent, source, target),
                explored,
            )
        for neighbor in graph.successors(zone):
            if neighbor not in visited:
                visited.add(neighbor)
                parent[neighbor] = zone
                frontier.append(neighbor)
    return _result(graph, "BFS", (), explored)


def _reconstruct_path(
    parent: dict[str, str],
    source: str,
    target: str,
) -> tuple[str, ...]:
    """Follow predecessor links from a reached goal back to the source."""
    path = [target]
    while path[-1] != source:
        path.append(parent[path[-1]])
    path.reverse()
    return tuple(path)
