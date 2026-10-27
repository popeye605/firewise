"""Template CSV converter; this is not a parser for any specific vendor."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

COLUMN_MAPPING = {
    "id": "Name",
    "src_ip": "Source",
    "dst_ip": "Destination",
    "service": "Service",
    "action": "Action",
    "log": "Logging",
}
DEFAULT_VALUES = {
    "src_zone": "LAN",
    "dst_zone": "WAN",
}
FIREWISE_COLUMNS = (
    "id",
    "src_zone",
    "dst_zone",
    "src_ip",
    "dst_ip",
    "service",
    "action",
    "log",
)


def convert_csv(input_path: Path, output_path: Path) -> None:
    """Convert an export using the mapping and default zones above."""
    with input_path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            raise ValueError("Input CSV is empty or has no header.")
        missing = sorted(set(COLUMN_MAPPING.values()) - set(reader.fieldnames))
        if missing:
            raise ValueError("Input CSV is missing columns: " + ", ".join(missing))
        with output_path.open("w", encoding="utf-8", newline="") as destination:
            writer = csv.DictWriter(destination, fieldnames=FIREWISE_COLUMNS)
            writer.writeheader()
            for row in reader:
                converted = dict(DEFAULT_VALUES)
                converted.update(
                    {
                        target: (row.get(source_column) or "").strip()
                        for target, source_column in COLUMN_MAPPING.items()
                    }
                )
                writer.writerow(converted)


def main() -> None:
    """Parse command-line paths and run the conversion."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Vendor-style input CSV")
    parser.add_argument("--output", type=Path, required=True, help="FireWise output CSV")
    arguments = parser.parse_args()
    convert_csv(arguments.input, arguments.output)


if __name__ == "__main__":
    main()
