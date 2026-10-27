"""Tests for the vendor CSV conversion template."""

import csv

from core.loader import load_rules
from scripts.convert_example import convert_csv


def test_converter_converts_five_vendor_rows(tmp_path) -> None:
    source = tmp_path / "vendor.csv"
    destination = tmp_path / "firewise.csv"
    source.write_text(
        "Name,Source,Destination,Service,Action,Logging\n"
        "R1,10.0.0.0/24,192.0.2.0/24,https,permit,yes\n"
        "R2,10.0.1.0/24,192.0.2.0/24,dns,permit,no\n"
        "R3,10.0.2.0/24,192.0.2.0/24,ssh,deny,true\n"
        "R4,10.0.3.0/24,192.0.2.0/24,tcp/8000,permit,enabled\n"
        "R5,10.0.4.0/24,192.0.2.0/24,icmp,deny,off\n",
        encoding="utf-8",
        newline="",
    )

    convert_csv(source, destination)

    with destination.open("r", encoding="utf-8", newline="") as output:
        rows = list(csv.DictReader(output))
    rules = load_rules(destination)

    assert len(rows) == len(rules) == 5
    assert all(row["src_zone"] == "LAN" and row["dst_zone"] == "WAN" for row in rows)
    assert [rule.id for rule in rules] == ["R1", "R2", "R3", "R4", "R5"]
