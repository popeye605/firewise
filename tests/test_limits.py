"""Upload and analysis protections for large firewall policies."""

from io import StringIO
from time import perf_counter

import pytest

from core.checks import analyze_rules
from ai.genetic import optimize_rules
from core.loader import MAX_FILE_BYTES, MAX_RULES, RuleLoadError, load_rules

HEADER = "id,src_zone,dst_zone,src_ip,dst_ip,service,action,log\n"
ROW = "r{index},Staff,Database,10.0.0.0/24,192.0.2.0/24,https,permit,true\n"


def test_load_rules_rejects_file_over_size_limit(tmp_path) -> None:
    path = tmp_path / "large.csv"
    path.write_bytes(b"x" * (MAX_FILE_BYTES + 1))

    with pytest.raises(RuleLoadError, match="maximum file size"):
        load_rules(path)


def test_load_rules_rejects_too_many_rows() -> None:
    content = HEADER + "".join(ROW.format(index=index) for index in range(MAX_RULES + 1))

    with pytest.raises(RuleLoadError, match="maximum of 5,000 firewall rules"):
        load_rules(StringIO(content))


def test_one_thousand_generated_rules_analyze_under_ten_seconds() -> None:
    rows = []
    for index in range(1000):
        source_ip = f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}/32"
        rows.append(
            f"r{index},Staff,Database,{source_ip},192.0.2.0/24,https,permit,true\n"
        )
    content = HEADER + "".join(rows)
    rules = load_rules(StringIO(content))

    started = perf_counter()
    findings = analyze_rules(rules)
    elapsed = perf_counter() - started

    assert len(rules) == 1000
    assert findings == []
    assert elapsed < 10


def test_optimizer_reports_limits_for_large_zone_pair() -> None:
    content = HEADER + "".join(ROW.format(index=index) for index in range(201))
    rules = load_rules(StringIO(content))

    result = optimize_rules(rules)

    assert result.packet_count_cap == 100
    assert result.search_population_cap == 8
    assert result.search_generation_cap == 6
    assert result.verification.packets_tested <= result.packet_count_cap
