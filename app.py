"""Streamlit user interface for the defensive FireWise rule checker."""

from __future__ import annotations

import csv
import hashlib
from io import StringIO

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

from ai.astar import (
    PathSearchResult,
    astar_search,
    breadth_first_search,
    build_zone_graph,
)
from ai.genetic import OptimizationResult, optimize_rules
from core.checks import Finding, ProblemType, Severity, analyze_rules
from core.loader import RuleLoadError, load_demo_rules, load_rules
from core.models import Rule
from core.score import calculate_health_score
from reports.html_report import generate_html_report

st.set_page_config(
    page_title="FireWise | Firewall Rule Health",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def _invalidate_results() -> None:
    """Clear derived results after the source policy changes."""
    st.session_state["attack_results"] = None
    st.session_state["optimization_result"] = None
    st.session_state["attack_path"] = None


def _set_rules(rules: list[Rule], source_name: str) -> None:
    """Store a new policy and invalidate results derived from the old one."""
    st.session_state["rules"] = rules
    st.session_state["source_name"] = source_name
    st.session_state["load_error"] = None
    _invalidate_results()


def _rule_csv(rules: tuple[Rule, ...]) -> str:
    """Serialize recommended rules to the documented CSV input format."""
    output = StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        ("id", "src_zone", "dst_zone", "src_ip", "dst_ip", "service", "action", "log")
    )
    for rule in rules:
        if rule.service.protocol == "any":
            service = "any"
        elif rule.service.ports:
            port_descriptions = [
                str(item.start) if item.start == item.end else f"{item.start}-{item.end}"
                for item in rule.service.ports
            ]
            service = ";".join(
                f"{rule.service.protocol}/{port}" for port in port_descriptions
            )
        else:
            service = rule.service.protocol
        writer.writerow(
            (
                rule.id,
                rule.src_zone,
                rule.dst_zone,
                ";".join(str(network) for network in rule.src_networks),
                ";".join(str(network) for network in rule.dst_networks),
                service,
                rule.action.value,
                "yes" if rule.log else "no",
            )
        )
    return output.getvalue()


def _render_zone_graph(
    rules: list[Rule],
    path_result: PathSearchResult | None,
) -> None:
    """Display the directed permit graph and highlight any selected route."""
    graph = build_zone_graph(rules)
    if graph.number_of_nodes() == 0:
        st.info("There are no permit rules to show as zone transitions.")
        return

    highlighted_rules = set(path_result.rule_ids) if path_result and path_result.found else set()
    network = Network(
        height="500px",
        width="100%",
        directed=True,
        bgcolor="#0e1117",
        font_color="#f0f2f6",
        cdn_resources="in_line",
    )
    network.barnes_hut()
    for zone in graph.nodes:
        network.add_node(zone, label=zone, title=f"Zone: {zone}", color="#4b91e2")
    for source, destination, key, details in graph.edges(keys=True, data=True):
        selected = str(details["rule_id"]) in highlighted_rules
        network.add_edge(
            source,
            destination,
            title=f"Rule {details['rule_id']} | cost {details['cost']:.3f}",
            label=str(details["rule_id"]),
            color="#ff4b4b" if selected else "#8c98a8",
            width=5 if selected else 1,
            arrows="to",
        )
    components.html(network.generate_html(), height=520, scrolling=False)


def _render_home() -> None:
    """Render demo-data loading and validated CSV upload controls."""
    st.title("🛡️ FireWise")
    st.subheader("Understand and improve firewall rule health")
    st.write(
        "FireWise checks rule hygiene, explains policy risks, compares attack-path "
        "searches, and recommends a behavior-tested rule list for review."
    )
    st.warning(
        "Educational and defensive use only. Recommendations are not applied to "
        "firewalls; review them with your network-security team."
    )

    left, right = st.columns(2)
    with left:
        st.markdown("#### Start with sample data")
        if st.button("Load Demo Data", type="primary", width="stretch"):
            try:
                _set_rules(load_demo_rules(), "Bundled demo data")
                st.rerun()
            except RuleLoadError as exc:
                st.error(f"Could not load demo data: {exc}")

    with right:
        st.markdown("#### Or upload a rule list")
        uploaded_file = st.file_uploader(
            "Choose a CSV firewall rule list",
            type=["csv"],
            help=(
                "Required columns: id, src_zone, dst_zone, src_ip, dst_ip, "
                "service, action, log."
            ),
            key="rule_csv_upload",
        )
        if uploaded_file is not None:
            content = uploaded_file.getvalue()
            upload_signature = (
                uploaded_file.name,
                hashlib.sha256(content).hexdigest(),
            )
            if st.session_state.get("upload_signature") != upload_signature:
                try:
                    text = content.decode("utf-8-sig")
                    parsed_rules = load_rules(StringIO(text))
                    _set_rules(parsed_rules, uploaded_file.name)
                    st.session_state["upload_signature"] = upload_signature
                    st.rerun()
                except (UnicodeDecodeError, RuleLoadError) as exc:
                    _set_rules([], uploaded_file.name)
                    st.session_state["upload_signature"] = upload_signature
                    st.session_state["load_error"] = f"CSV could not be loaded: {exc}"
                    st.rerun()

    if st.session_state["rules"]:
        st.success(
            f"Active policy: {st.session_state['source_name']} "
            f"({len(st.session_state['rules'])} rules). Open the other tabs to explore it."
        )
    else:
        st.info("Load the demo policy or upload a CSV to begin.")


def _render_dashboard(rules: list[Rule], findings: list[Finding]) -> None:
    """Render the policy health gauge, summary metrics, and finding chart."""
    score = calculate_health_score(rules, findings)
    counts = score.problem_counts
    high_risk_rule_ids = {
        finding.rule_id for finding in findings if finding.severity is Severity.HIGH
    }
    redundant_count = counts.get(ProblemType.SHADOWED.value, 0) + counts.get(
        ProblemType.DUPLICATE.value, 0
    )
    unlogged_count = counts.get(ProblemType.UNLOGGED_PERMIT.value, 0)

    st.header("Policy health dashboard")
    gauge, metrics = st.columns([1, 2])
    with gauge:
        figure = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=score.score,
                title={"text": "Health score"},
                number={"suffix": " / 100"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#34d399"},
                    "steps": [
                        {"range": [0, 40], "color": "#571d26"},
                        {"range": [40, 70], "color": "#61441a"},
                        {"range": [70, 100], "color": "#164e42"},
                    ],
                },
            )
        )
        figure.update_layout(height=260, margin={"l": 20, "r": 20, "t": 55, "b": 5})
        st.plotly_chart(figure, width="stretch")
    with metrics:
        first_row = st.columns(2)
        first_row[0].metric("Total rules", len(rules))
        first_row[1].metric("High-risk rules", len(high_risk_rule_ids))
        second_row = st.columns(2)
        second_row[0].metric("Redundant findings", redundant_count)
        second_row[1].metric("Unlogged permits", unlogged_count)
        st.caption(
            f"{score.findings_count} total findings · "
            f"{score.penalty_points} / {score.maximum_points} penalty points"
        )

    all_types = [problem_type.value for problem_type in ProblemType]
    chart_data = pd.DataFrame(
        {
            "Problem type": all_types,
            "Findings": [counts.get(problem_type, 0) for problem_type in all_types],
        }
    )
    chart = px.bar(
        chart_data,
        x="Problem type",
        y="Findings",
        color="Findings",
        color_continuous_scale=["#3b82f6", "#f59e0b", "#ef4444"],
    )
    chart.update_layout(showlegend=False, coloraxis_showscale=False)
    st.plotly_chart(chart, width="stretch")


def _render_problems(findings: list[Finding]) -> None:
    """Render a severity-filtered table with expandable explanations."""
    st.header("Rule problems")
    severities = ["All", *(severity.value for severity in Severity)]
    selected_severity = st.selectbox("Filter by severity", severities)
    visible = [
        finding
        for finding in findings
        if selected_severity == "All" or finding.severity.value == selected_severity
    ]
    if not visible:
        st.success("No findings match this filter.")
        return

    table = pd.DataFrame(
        [
            {
                "Severity": finding.severity.value,
                "Rule": finding.rule_id,
                "Problem": finding.problem_type.value,
                "Related rules": ", ".join(finding.related_rule_ids) or "—",
            }
            for finding in visible
        ]
    )
    severity_colors = {"High": "#7f1d1d", "Medium": "#78350f", "Low": "#713f12"}
    st.dataframe(
        table.style.map(
            lambda value: (
                f"background-color: {severity_colors[value]}; color: white"
                if value in severity_colors
                else ""
            ),
            subset=["Severity"],
        ),
        width="stretch",
        hide_index=True,
    )
    for finding in visible:
        icon = {"High": "🔴", "Medium": "🟠", "Low": "🟡"}[finding.severity.value]
        with st.expander(
            f"{icon} {finding.severity.value} · {finding.rule_id} · "
            f"{finding.problem_type.value}"
        ):
            st.write(finding.explanation)
            st.markdown(f"**Suggested fix:** {finding.suggested_fix}")
            if finding.related_rule_ids:
                st.caption("Related rules: " + ", ".join(finding.related_rule_ids))


def _render_network_map(rules: list[Rule]) -> None:
    """Render zone selection, attack-path comparison, and interactive graph."""
    st.header("Network map and attack path")
    graph = build_zone_graph(rules)
    zones = sorted(graph.nodes, key=str.casefold)
    if not zones:
        st.info("No permit edges are available to build the zone map.")
        return
    if len(zones) == 1:
        st.info("Add permit rules connecting at least two zones to find an attack path.")
        _render_zone_graph(rules, None)
        return

    source_default = zones.index("Internet") if "Internet" in zones else 0
    target_default = (
        zones.index("Database")
        if "Database" in zones
        else min(1, len(zones) - 1)
    )
    source_col, target_col, action_col = st.columns([2, 2, 1])
    source = source_col.selectbox(
        "From zone", zones, index=source_default, key="attack_source"
    )
    target = target_col.selectbox(
        "To zone", zones, index=target_default, key="attack_target"
    )
    if action_col.button("Find Attack Path", type="primary", width="stretch"):
        try:
            st.session_state["attack_results"] = (
                astar_search(graph, source, target),
                breadth_first_search(graph, source, target),
            )
            st.session_state["attack_request"] = (source, target)
        except ValueError as exc:
            st.error(f"Path search failed: {exc}")
            st.session_state["attack_results"] = None

    results = st.session_state.get("attack_results")
    if st.session_state.get("attack_request") != (source, target):
        results = None
    selected_result: PathSearchResult | None = None
    if results:
        astar_result, bfs_result = results
        if astar_result.path and bfs_result.path:
            selected_result = astar_result
            st.success("A* lowest-cost path: " + " → ".join(astar_result.path))
            st.caption(
                f"Rules: {', '.join(astar_result.rule_ids)} · "
                f"Total risk cost: {astar_result.total_cost:.3f}"
            )
        else:
            st.warning(f"No permitted route found from {source} to {target}.")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Algorithm": result.algorithm,
                        "Path": " → ".join(result.path) if result.path else "No route",
                        "Cost": (
                            round(result.total_cost, 3)
                            if result.found
                            else "—"
                        ),
                        "Nodes explored": result.nodes_explored,
                    }
                    for result in (astar_result, bfs_result)
                ]
            ),
            width="stretch",
            hide_index=True,
        )
    _render_zone_graph(rules, selected_result)


def _render_optimizer(rules: list[Rule]) -> None:
    """Run optimization on request and show review-only results."""
    st.header("Recommendation optimizer")
    st.warning(
        "The optimizer recommends a rule list only. It never applies changes "
        "to a firewall; review exported rules before use."
    )
    if st.button("Run Optimizer", type="primary"):
        progress_bar = st.progress(0.0, text="Starting per-zone-pair optimization…")
        try:
            result = optimize_rules(
                rules,
                progress_callback=lambda progress: progress_bar.progress(
                    min(progress, 1.0),
                    text=f"Optimizing zone pairs: {progress:.0%}",
                ),
            )
        except ValueError as exc:
            progress_bar.empty()
            st.error(f"Optimization failed: {exc}")
        else:
            progress_bar.progress(1.0, text="Packet verification complete.")
            st.session_state["optimization_result"] = result

    result: OptimizationResult | None = st.session_state.get("optimization_result")
    if result is None:
        st.info("Run the optimizer to see a recommendation and verification results.")
        return

    if result.candidate_rejected:
        st.error(
            "A candidate changed tested packet behavior and was rejected. "
            "The recommended list has been restored to the original policy."
        )
    elif result.verification.equivalent:
        st.success(
            "No allow/deny differences were found in the tested packet set. "
            "This is not a formal proof for all possible packets."
        )
    comparison = pd.DataFrame(
        [
            {
                "Measure": "Rule count",
                "Before": result.before_rule_count,
                "Recommended": result.after_rule_count,
            },
            {
                "Measure": "Permit risk score",
                "Before": result.before_risk_score,
                "Recommended": result.after_risk_score,
            },
            {
                "Measure": "Rule-count reduction",
                "Before": "—",
                "Recommended": f"{result.reduction_percent:.1f}%",
            },
        ]
    )
    st.dataframe(comparison, use_container_width=True, hide_index=True)
    verification_col, fitness_col = st.columns(2)
    verification_col.metric(
        "Behavior verification",
        "Passed" if result.verification.equivalent else "Failed",
        delta=f"{result.verification.packets_tested:,} packets compared",
    )
    verification_col.caption(
        f"{result.verification.boundary_packets_tested:,} boundary-derived + "
        f"{result.verification.random_packets_tested:,} random packets · "
        f"{result.verification.mismatch_count} mismatches"
    )
    if result.fitness_history:
        fitness_chart = px.line(
            x=list(range(len(result.fitness_history))),
            y=result.fitness_history,
            labels={"x": "Generation", "y": "Best fitness"},
            title="Best fitness by generation",
        )
        fitness_col.plotly_chart(fitness_chart, width="stretch")
    st.download_button(
        "Download recommended CSV for review",
        data=_rule_csv(result.recommended_rules),
        file_name="firewise_recommended_rules.csv",
        mime="text/csv",
        disabled=result.candidate_rejected,
    )
    if result.verification.mismatches:
        with st.expander("Show example mismatched packets"):
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Source": f"{mismatch.packet.src_zone} · {mismatch.packet.src_ip}",
                            "Destination": (
                                f"{mismatch.packet.dst_zone} · "
                                f"{mismatch.packet.dst_ip}"
                            ),
                            "Service": (
                                f"{mismatch.packet.protocol}/"
                                f"{mismatch.packet.dst_port}"
                            ),
                            "Before": "Allowed" if mismatch.before_allowed else "Blocked",
                            "After": "Allowed" if mismatch.after_allowed else "Blocked",
                        }
                        for mismatch in result.verification.mismatches
                    ]
                ),
                width="stretch",
                hide_index=True,
            )


def _render_report(
    rules: list[Rule],
    findings: list[Finding],
    source_name: str,
) -> None:
    """Render a downloadable, self-contained HTML analysis report."""
    st.header("HTML report")
    if not rules:
        st.info("Load a policy on the Home tab to generate its HTML report.")
        return

    try:
        report_html = generate_html_report(
            source_name=source_name,
            rules=rules,
            findings=findings,
            health_score=calculate_health_score(rules, findings),
            attack_results=st.session_state.get("attack_results"),
            optimization_result=st.session_state.get("optimization_result"),
        )
    except (TypeError, ValueError) as exc:
        st.error(f"Could not generate the HTML report: {exc}")
        return
    st.caption(
        "The report includes the current policy score and findings, plus any "
        "attack-path and optimizer results recorded in this session."
    )
    st.download_button(
        "Download HTML report",
        data=report_html,
        file_name="firewise_health_report.html",
        mime="text/html",
        type="primary",
    )
    with st.expander("Preview report summary"):
        st.markdown(
            f"**Source:** {source_name}  \n"
            f"**Rules:** {len(rules)}  \n"
            f"**Health score:** {calculate_health_score(rules, findings).score}/100  \n"
            f"**Findings:** {len(findings)}"
        )


def main() -> None:
    """Render FireWise tabs and all analysis views for the active policy."""
    st.session_state.setdefault("rules", [])
    st.session_state.setdefault("source_name", "")
    st.session_state.setdefault("attack_results", None)
    st.session_state.setdefault("attack_request", None)
    st.session_state.setdefault("optimization_result", None)
    st.session_state.setdefault("attack_path", None)
    st.session_state.setdefault("upload_signature", None)
    st.session_state.setdefault("load_error", None)

    rules: list[Rule] = st.session_state["rules"]
    findings = analyze_rules(rules) if rules else []
    if st.session_state["load_error"]:
        st.error(st.session_state["load_error"])
    st.sidebar.title("🛡️ FireWise")
    st.sidebar.caption("Defensive firewall-rule health checker")
    if rules:
        st.sidebar.success(f"{st.session_state['source_name']} · {len(rules)} rules")
        if st.sidebar.button("Clear loaded policy"):
            _set_rules([], "")
            st.session_state["upload_signature"] = None
            st.rerun()
    else:
        st.sidebar.info("Load demo data or upload a CSV on Home.")

    home_tab, dashboard_tab, problems_tab, network_tab, optimizer_tab, report_tab = (
        st.tabs(
            [
                "Home",
                "Dashboard",
                "Problems",
                "Network Map",
                "Optimizer",
                "Report",
            ]
        )
    )
    with home_tab:
        _render_home()
    with dashboard_tab:
        if rules:
            _render_dashboard(rules, findings)
        else:
            st.info("Load a policy on the Home tab to see the dashboard.")
    with problems_tab:
        if rules:
            _render_problems(findings)
        else:
            st.info("Load a policy on the Home tab to inspect problems.")
    with network_tab:
        if rules:
            _render_network_map(rules)
        else:
            st.info("Load a policy on the Home tab to explore zone paths.")
    with optimizer_tab:
        if rules:
            _render_optimizer(rules)
        else:
            st.info("Load a policy on the Home tab to optimize a recommendation.")
    with report_tab:
        _render_report(
            rules,
            findings,
            st.session_state["source_name"] or "Uploaded firewall policy",
        )


if __name__ == "__main__":
    main()
