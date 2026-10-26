"""Generate downloadable, self-contained HTML audit reports."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Sequence

from ai.astar import PathSearchResult
from ai.genetic import OptimizationResult
from core.checks import Finding
from core.models import Rule
from core.score import HealthScore


def _cell(value: object) -> str:
    """Escape a value before placing it in an HTML table cell."""
    return f"<td>{escape(str(value))}</td>"


def _findings_table(findings: Sequence[Finding]) -> str:
    """Render findings as an escaped table, including remediation advice."""
    if not findings:
        return "<p class='good'>No findings were detected.</p>"
    rows = []
    for finding in findings:
        severity_class = finding.severity.value.lower()
        rows.append(
            "<tr>"
            + _cell(finding.severity.value)
            + _cell(finding.rule_id)
            + _cell(finding.problem_type.value)
            + _cell(finding.explanation)
            + _cell(finding.suggested_fix)
            + _cell(", ".join(finding.related_rule_ids) or "—")
            + "</tr>"
        )
        rows[-1] = rows[-1].replace(
            f"<td>{escape(finding.severity.value)}</td>",
            f"<td class='{severity_class}'>{escape(finding.severity.value)}</td>",
            1,
        )
    return (
        "<table><thead><tr><th>Severity</th><th>Rule</th><th>Problem</th>"
        "<th>Explanation</th><th>Suggested fix</th><th>Related rules</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _path_section(
    attack_results: tuple[PathSearchResult, PathSearchResult] | None,
) -> str:
    """Render the optional A* versus BFS path comparison."""
    if attack_results is None:
        return "<p>No attack-path search has been run in this session.</p>"
    rows = []
    for result in attack_results:
        path = " → ".join(result.path) if result.path else "No route"
        cost = f"{result.total_cost:.3f}" if result.found else "—"
        rows.append(
            "<tr>"
            + _cell(result.algorithm)
            + _cell(path)
            + _cell(", ".join(result.rule_ids) or "—")
            + _cell(cost)
            + _cell(result.nodes_explored)
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>Algorithm</th><th>Path</th><th>Rules</th>"
        "<th>Cost</th><th>Nodes explored</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _optimizer_section(result: OptimizationResult | None) -> str:
    """Render optional optimizer metrics and packet-verification evidence."""
    if result is None:
        return "<p>No optimizer run has been recorded in this session.</p>"
    verification = result.verification
    status = "Passed" if verification.equivalent else "Failed"
    rows = [
        ("Rules before", result.before_rule_count),
        ("Rules recommended", result.after_rule_count),
        ("Rule-count reduction", f"{result.reduction_percent:.1f}%"),
        ("Permit risk before", result.before_risk_score),
        ("Permit risk recommended", result.after_risk_score),
        ("Packet verification", status),
        ("Packets compared", verification.packets_tested),
        ("Boundary-derived packets", verification.boundary_packets_tested),
        ("Random packets", verification.random_packets_tested),
        ("Decision mismatches", verification.mismatch_count),
        ("Candidate rejected", "Yes" if result.candidate_rejected else "No"),
        ("Fitness generations recorded", len(result.fitness_history)),
    ]
    table_rows = "".join(
        "<tr>" + _cell(label) + _cell(value) + "</tr>" for label, value in rows
    )
    return (
        "<div class='notice'>Recommendations are for review only. They are not "
        "applied to a firewall. Packet testing is not a formal proof for every "
        "possible packet.</div>"
        "<table><thead><tr><th>Measure</th><th>Result</th></tr></thead><tbody>"
        + table_rows
        + "</tbody></table>"
    )


def generate_html_report(
    *,
    source_name: str,
    rules: Sequence[Rule],
    findings: Sequence[Finding],
    health_score: HealthScore,
    attack_results: tuple[PathSearchResult, PathSearchResult] | None = None,
    optimization_result: OptimizationResult | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Build a self-contained HTML report with escaped user-provided content."""
    timestamp = generated_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp_text = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    problem_rows = "".join(
        "<tr>" + _cell(name) + _cell(count) + "</tr>"
        for name, count in sorted(health_score.problem_counts.items())
    )
    if not problem_rows:
        problem_rows = "<tr><td colspan='2'>No findings</td></tr>"

    title = "FireWise Firewall Health Report"
    safe_title = escape(title)
    safe_source = escape(source_name)
    finding_count = len(findings)
    rule_count = len(rules)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title}</title>
<style>
:root {{ color-scheme: dark; font-family: Segoe UI, Arial, sans-serif; background: #0e1117; color: #e6edf3; }}
body {{ max-width: 1100px; margin: 2rem auto; padding: 0 1rem 3rem; line-height: 1.5; }}
h1, h2 {{ color: #93c5fd; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }}
.card {{ background: #17202b; border: 1px solid #334155; border-radius: 8px; padding: 1rem; }}
.value {{ display: block; font-size: 1.7rem; font-weight: 700; }}
.muted {{ color: #aab6c5; }}
.notice {{ border-left: 4px solid #f59e0b; background: #2b2416; padding: .8rem 1rem; margin: 1rem 0; }}
.good {{ color: #6ee7b7; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0 2rem; font-size: .92rem; }}
th, td {{ border: 1px solid #334155; padding: .6rem; text-align: left; vertical-align: top; overflow-wrap: anywhere; }}
th {{ background: #1e293b; }}
.high {{ color: #fca5a5; font-weight: 700; }}
.medium {{ color: #fdba74; font-weight: 700; }}
.low {{ color: #fde047; font-weight: 700; }}
@media print {{ :root {{ color-scheme: light; background: white; color: #111; }} body {{ max-width: none; }} .card, th {{ background: #f1f5f9; }} }}
</style>
</head>
<body>
<header>
<h1>{safe_title}</h1>
<p class="muted">Generated {escape(timestamp_text)} · Source: {safe_source}</p>
</header>
<section class="summary" aria-label="Policy summary">
<div class="card"><span class="muted">Health score</span><span class="value">{health_score.score} / 100</span></div>
<div class="card"><span class="muted">Total rules</span><span class="value">{rule_count}</span></div>
<div class="card"><span class="muted">Findings</span><span class="value">{finding_count}</span></div>
<div class="card"><span class="muted">Penalty points</span><span class="value">{health_score.penalty_points} / {health_score.maximum_points}</span></div>
</section>
<h2>Findings by type</h2>
<table><thead><tr><th>Problem</th><th>Count</th></tr></thead><tbody>{problem_rows}</tbody></table>
<h2>Problem details and suggested fixes</h2>
{_findings_table(findings)}
<h2>Attack-path comparison</h2>
{_path_section(attack_results)}
<h2>Optimizer results</h2>
{_optimizer_section(optimization_result)}
<footer><p class="muted">FireWise is an educational defensive tool. Verify all results and review every recommendation before operational use.</p></footer>
</body>
</html>
"""
