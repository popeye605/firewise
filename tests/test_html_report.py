"""Tests for downloadable self-contained HTML audit reports."""

from datetime import datetime, timezone

from ai.astar import astar_search, breadth_first_search, build_zone_graph
from ai.genetic import optimize_rules
from core.checks import analyze_rules
from core.loader import load_demo_rules
from core.score import calculate_health_score
from reports.html_report import generate_html_report


def test_report_is_standalone_and_includes_findings_score_and_timestamp() -> None:
    rules = load_demo_rules()
    findings = analyze_rules(rules)
    score = calculate_health_score(rules, findings)
    report = generate_html_report(
        source_name="Sample policy",
        rules=rules,
        findings=findings,
        health_score=score,
        generated_at=datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc),
    )

    assert report.startswith("<!doctype html>")
    assert "<meta charset=\"utf-8\">" in report
    assert "Sample policy" in report
    assert "2026-01-02 03:04 UTC" in report
    assert f"{score.score} / 100" in report
    assert "Any-Any rule" in report
    assert "Suggested fix" in report
    assert "https://" not in report


def test_report_escapes_untrusted_source_and_finding_text() -> None:
    rules = load_demo_rules()[:1]
    findings = analyze_rules(rules)
    findings[0] = type(findings[0])(
        rule_id=findings[0].rule_id,
        problem_type=findings[0].problem_type,
        severity=findings[0].severity,
        explanation="<img src=x onerror=alert(1)>",
        suggested_fix="<script>fix()</script>",
    )
    report = generate_html_report(
        source_name="<b>upload</b>",
        rules=rules,
        findings=findings,
        health_score=calculate_health_score(rules, findings),
    )

    assert "<b>upload</b>" not in report
    assert "&lt;b&gt;upload&lt;/b&gt;" in report
    assert "<img src=x" not in report
    assert "&lt;img src=x onerror=alert(1)&gt;" in report
    assert "&lt;script&gt;fix()&lt;/script&gt;" in report


def test_report_includes_optional_attack_and_optimizer_results() -> None:
    rules = load_demo_rules()
    findings = analyze_rules(rules)
    graph = build_zone_graph(rules)
    attack_results = (
        astar_search(graph, "Internet", "Database"),
        breadth_first_search(graph, "Internet", "Database"),
    )
    optimization = optimize_rules(
        rules,
        population_size=8,
        generations=3,
        random_packet_count=20,
    )
    report = generate_html_report(
        source_name="Demo",
        rules=rules,
        findings=findings,
        health_score=calculate_health_score(rules, findings),
        attack_results=attack_results,
        optimization_result=optimization,
    )

    assert "Attack-path comparison" in report
    assert "A*" in report
    assert "BFS" in report
    assert "Optimizer results" in report
    assert "Boundary-derived packets" in report
    assert "Random packets" in report
    assert "Recommendations are for review only" in report


def test_report_handles_clean_policy_and_missing_optional_results() -> None:
    from tests.helpers import make_rule

    rules = [make_rule("clean")]
    findings = analyze_rules(rules, untrusted_zones=set(), trusted_zones=set())
    report = generate_html_report(
        source_name="Clean policy",
        rules=rules,
        findings=findings,
        health_score=calculate_health_score(rules, findings),
    )

    assert "No findings were detected" in report
    assert "No attack-path search has been run" in report
    assert "No optimizer run has been recorded" in report


def test_report_includes_escaped_data_warnings_and_removed_deny_warning() -> None:
    from dataclasses import replace

    rules = load_demo_rules()
    result = optimize_rules(
        rules,
        population_size=8,
        generations=3,
        random_packet_count=20,
    )
    result = replace(result, removed_deny_rules=("R031",))
    report = generate_html_report(
        source_name="Demo",
        rules=rules,
        findings=analyze_rules(rules),
        health_score=calculate_health_score(rules, analyze_rules(rules)),
        optimization_result=result,
        data_warnings=["CSV line 7: <untrusted> warning"],
    )

    assert "<h2>Data warnings</h2>" in report
    assert "CSV line 7: &lt;untrusted&gt; warning" in report
    assert "These deny rules were removed; their logging is lost: R031" in report
