"""CSV loading and normalization for firewall rules."""

from __future__ import annotations

import csv
import ipaddress
from pathlib import Path
import re
from typing import TextIO

from core.models import Action, IPAddressNetwork, PortRange, Rule, ServiceMatch

REQUIRED_COLUMNS = (
    "id",
    "src_zone",
    "dst_zone",
    "src_ip",
    "dst_ip",
    "service",
    "action",
    "log",
)

_SERVICE_ALIASES: dict[str, ServiceMatch] = {
    "any": ServiceMatch("any"),
    "all": ServiceMatch("any"),
    "icmp": ServiceMatch("icmp"),
    "icmpv6": ServiceMatch("icmpv6"),
    "tcp": ServiceMatch("tcp"),
    "udp": ServiceMatch("udp"),
    "http": ServiceMatch("tcp", (PortRange(80, 80),)),
    "https": ServiceMatch("tcp", (PortRange(443, 443),)),
    "ssh": ServiceMatch("tcp", (PortRange(22, 22),)),
    "dns": ServiceMatch("udp", (PortRange(53, 53),)),
    "rdp": ServiceMatch("tcp", (PortRange(3389, 3389),)),
    "ntp": ServiceMatch("udp", (PortRange(123, 123),)),
    "ftp": ServiceMatch("tcp", (PortRange(21, 21),)),
    "smtp": ServiceMatch("tcp", (PortRange(25, 25),)),
    "smtps": ServiceMatch("tcp", (PortRange(465, 465),)),
    "submission": ServiceMatch("tcp", (PortRange(587, 587),)),
    "imap": ServiceMatch("tcp", (PortRange(143, 143),)),
    "imaps": ServiceMatch("tcp", (PortRange(993, 993),)),
    "pop3": ServiceMatch("tcp", (PortRange(110, 110),)),
    "pop3s": ServiceMatch("tcp", (PortRange(995, 995),)),
    "mysql": ServiceMatch("tcp", (PortRange(3306, 3306),)),
    "postgres": ServiceMatch("tcp", (PortRange(5432, 5432),)),
    "mssql": ServiceMatch("tcp", (PortRange(1433, 1433),)),
    "ldap": ServiceMatch("tcp", (PortRange(389, 389),)),
    "ldaps": ServiceMatch("tcp", (PortRange(636, 636),)),
    "smb": ServiceMatch("tcp", (PortRange(445, 445),)),
    "telnet": ServiceMatch("tcp", (PortRange(23, 23),)),
    "snmp": ServiceMatch("udp", (PortRange(161, 161),)),
    "syslog": ServiceMatch("udp", (PortRange(514, 514),)),
}
_SERVICE_PATTERN = re.compile(
    r"^(tcp|udp)(?:/(\d+)(?:-(\d+))?)?$",
    re.IGNORECASE,
)
_PORT_PATTERN = re.compile(r"^(\d+)(?:-(\d+))?$")
_SERVICE_LIST_SEPARATOR = re.compile(r"[;,|]")


class RuleLoadError(ValueError):
    """Raised when input cannot be converted into valid firewall rules."""


def _parse_networks(
    value: str,
    field_name: str,
    line_number: int,
    warnings: list[str],
) -> tuple[IPAddressNetwork, ...]:
    """Parse one or more semicolon-separated IP networks."""
    entries = [entry.strip() for entry in value.replace(",", ";").split(";")]
    entries = [entry for entry in entries if entry]
    if not entries:
        raise RuleLoadError(f"{field_name} must contain an IP or 'any'.")

    networks: list[IPAddressNetwork] = []
    for entry in entries:
        if entry.lower() in {"any", "*"}:
            networks.extend(
                (
                    ipaddress.ip_network("0.0.0.0/0"),
                    ipaddress.ip_network("::/0"),
                )
            )
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise RuleLoadError(f"Invalid {field_name} network {entry!r}: {exc}") from exc
        if "/" in entry:
            address = ipaddress.ip_interface(entry).ip
            if address != network.network_address:
                warnings.append(
                    f"CSV line {line_number}: {field_name} '{entry}' has host bits "
                    f"set; treated as {network}."
                )
        if network.prefixlen == 0:
            warnings.append(
                f"CSV line {line_number}: {field_name} '{entry}' is a /0 network; "
                "consider writing 'any'."
            )
        networks.append(network)
    return tuple(networks)


def _parse_service(value: str) -> ServiceMatch:
    """Parse service aliases, bare protocols, and same-protocol service lists."""
    entries = [entry.strip().lower() for entry in _SERVICE_LIST_SEPARATOR.split(value)]
    if not entries or any(not entry for entry in entries):
        raise RuleLoadError(f"Invalid service list {value!r}: empty service entry.")

    protocols: set[str] = set()
    ports: list[PortRange] = []
    unrestricted_protocol = False
    previous_protocol: str | None = None
    for entry in entries:
        alias = _SERVICE_ALIASES.get(entry)
        if alias is not None:
            protocols.add(alias.protocol)
            previous_protocol = alias.protocol
            if alias.ports:
                ports.extend(alias.ports)
            else:
                unrestricted_protocol = True
            continue

        match = _SERVICE_PATTERN.fullmatch(entry)
        if match is not None:
            protocol, start, end = match.groups()
            protocol = protocol.lower()
            protocols.add(protocol)
            previous_protocol = protocol
            if start is None:
                unrestricted_protocol = True
                continue
        else:
            port_match = _PORT_PATTERN.fullmatch(entry)
            if port_match is None or previous_protocol not in {"tcp", "udp"}:
                raise RuleLoadError(
                    f"Unsupported service {entry!r}; use a known alias, 'any', "
                    "'icmp', 'tcp', 'udp', or a list of same-protocol "
                    "'tcp/PORT[-END]' or 'udp/PORT[-END]' entries."
                )
            protocol = previous_protocol
            start, end = port_match.groups()

        try:
            ports.append(
                PortRange(int(start), int(end) if end else int(start))
            )
        except ValueError as exc:
            raise RuleLoadError(f"Invalid service {entry!r}: {exc}") from exc

    if len(protocols) != 1:
        raise RuleLoadError(
            f"Service list {value!r} contains multiple protocols; "
            "split the rule into one row per protocol."
        )
    protocol = next(iter(protocols))
    if protocol == "any":
        return ServiceMatch("any")
    return ServiceMatch(protocol, () if unrestricted_protocol else tuple(ports))


def _parse_action(value: str) -> Action:
    """Normalize common permit/deny spellings."""
    normalized = value.strip().lower()
    if normalized in {"permit", "allow", "accept"}:
        return Action.PERMIT
    if normalized in {"deny", "block", "drop", "reject"}:
        return Action.DENY
    raise RuleLoadError(f"Unsupported action {value!r}; use permit or deny.")


def _parse_log(value: str) -> bool:
    """Parse an explicit boolean logging value."""
    normalized = value.strip().lower()
    if normalized in {"true", "yes", "1", "on", "enabled"}:
        return True
    if normalized in {"false", "no", "0", "off", "disabled"}:
        return False
    raise RuleLoadError(f"Invalid log value {value!r}; use yes/no or true/false.")


def _rule_from_row(
    row: dict[str, str | None],
    line_number: int,
    warnings: list[str],
) -> Rule:
    """Convert one CSV record and attach its line number to errors."""
    try:
        if None in row:
            raise RuleLoadError("row contains more values than the header.")
        raw_id = row.get("id") or ""
        if raw_id != raw_id.strip():
            warnings.append(
                f"CSV line {line_number}: rule id {raw_id!r} had leading or "
                f"trailing spaces; trimmed to {raw_id.strip()!r}."
            )
        values = {key: (value or "").strip() for key, value in row.items() if key}
        missing_values = [column for column in REQUIRED_COLUMNS if not values.get(column)]
        if missing_values:
            raise RuleLoadError(
                f"missing values for {', '.join(missing_values)}."
            )
        return Rule(
            id=values["id"],
            src_zone=values["src_zone"],
            dst_zone=values["dst_zone"],
            src_networks=_parse_networks(
                values["src_ip"], "src_ip", line_number, warnings
            ),
            dst_networks=_parse_networks(
                values["dst_ip"], "dst_ip", line_number, warnings
            ),
            service=_parse_service(values["service"]),
            action=_parse_action(values["action"]),
            log=_parse_log(values["log"]),
        )
    except (RuleLoadError, ValueError) as exc:
        raise RuleLoadError(f"CSV line {line_number}: {exc}") from exc


def load_rules(source: str | Path | TextIO) -> list[Rule]:
    """Load firewall rules from a CSV file path or open text stream."""
    rules, _ = load_rules_with_warnings(source)
    return rules


def load_rules_with_warnings(
    source: str | Path | TextIO,
) -> tuple[list[Rule], list[str]]:
    """Load firewall rules and return normalization warnings alongside them."""
    should_close = isinstance(source, (str, Path))
    try:
        stream = (
            Path(source).open("r", encoding="utf-8-sig", newline="")
            if should_close
            else source
        )
        reader = csv.DictReader(stream)
        if reader.fieldnames is None:
            raise RuleLoadError("CSV input is empty or missing a header.")
        headers = [header.strip() for header in reader.fieldnames if header is not None]
        missing_columns = [column for column in REQUIRED_COLUMNS if column not in headers]
        if missing_columns:
            raise RuleLoadError(
                f"CSV header is missing required columns: {', '.join(missing_columns)}."
            )
        if len(headers) != len(set(headers)):
            raise RuleLoadError("CSV header contains duplicate column names.")
        reader.fieldnames = headers

        rules: list[Rule] = []
        warnings: list[str] = []
        seen_ids: set[str] = set()
        for line_number, row in enumerate(reader, start=2):
            if row is None or all(not (value or "").strip() for value in row.values()):
                continue
            rule = _rule_from_row(row, line_number, warnings)
            if rule.id in seen_ids:
                raise RuleLoadError(f"CSV line {line_number}: duplicate rule id {rule.id!r}.")
            seen_ids.add(rule.id)
            rules.append(rule)
        if not rules:
            raise RuleLoadError("CSV contains a header but no firewall rules.")
        return rules, warnings
    except OSError as exc:
        raise RuleLoadError(f"Could not read rule CSV: {exc}") from exc
    finally:
        if should_close and "stream" in locals():
            stream.close()


def load_demo_rules() -> list[Rule]:
    """Load the bundled sample dataset, independent of the working directory."""
    demo_path = Path(__file__).resolve().parent.parent / "data" / "demo_rules.csv"
    return load_rules(demo_path)
