"""Run deterministic FireWise comparisons for all bundled CSV policies."""

from __future__ import annotations

from pathlib import Path

import networkx as nx

from ai.astar import astar_search, breadth_first_search, build_zone_graph
from ai.genetic import optimize_rules
from core.checks import DEFAULT_ZONE_TRUST, analyze_rules
from core.loader import load_demo_rules, load_rules
from core.models import Rule
from core.score import calculate_health_score

ROOT = Path(__file__).resolve().parent
EXPERIMENTS = (
    ("demo_rules", ROOT / "data" / "demo_rules.csv"),
    ("astar_demo", ROOT / "data" / "astar_demo.csv"),
    ("stress_rules", ROOT / "data" / "stress_rules.csv"),
)
SEED = 2026


def _sample_rules(name: str, path: Path) -> list[Rule]:
    """Load one bundled experiment policy."""
    return load_demo_rules() if name == "demo_rules" else load_rules(path)


def _path_node_totals(graph: nx.MultiDiGraph) -> tuple[int, int]:
    """Sum A* and BFS explored nodes over all reachable ordered zone pairs."""
    astar_nodes = 0
    bfs_nodes = 0
    zones = list(graph.nodes)
    for source in zones:
        for target in zones:
            if source == target or not nx.has_path(graph, source, target):
                continue
            astar_nodes += astar_search(graph, source, target).nodes_explored
            bfs_nodes += breadth_first_search(graph, source, target).nodes_explored
    return astar_nodes, bfs_nodes


def run_experiments() -> Path:
    """Run checks, path searches, and fixed-seed optimization for each sample."""
    rows: list[str] = []
    for name, path in EXPERIMENTS:
        rules = _sample_rules(name, path)
        findings = analyze_rules(rules, DEFAULT_ZONE_TRUST)
        score = calculate_health_score(rules, findings)
        graph = build_zone_graph(rules, zone_trust=DEFAULT_ZONE_TRUST)
        astar_nodes, bfs_nodes = _path_node_totals(graph)
        result = optimize_rules(
            rules,
            seed=SEED,
            random_packet_count=200,
            zone_trust=DEFAULT_ZONE_TRUST,
        )
        rows.append(
            "| "
            + " | ".join(
                (
                    name,
                    str(len(rules)),
                    str(len(findings)),
                    str(score.score),
                    str(astar_nodes),
                    str(bfs_nodes),
                    f"{result.before_rule_count} → {result.after_rule_count}",
                    f"{result.before_risk_score} → {result.after_risk_score}",
                    str(result.verification.packets_tested),
                )
            )
            + " |"
        )

    output = ROOT / "results" / "experiment_results.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "\n".join(
            (
                "# FireWise experiment results",
                "",
                f"Seed: `{SEED}`. Optimizer random packet budget: `200`.",
                "",
                "| Policy | Rules | Findings | Score | A* nodes | BFS nodes | Optimizer rules | Permit risk | Packets tested |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
                *rows,
                "",
            )
        ),
        encoding="utf-8",
    )
    return output


if __name__ == "__main__":
    print(run_experiments())
