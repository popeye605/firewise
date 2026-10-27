# FireWise CSV format

FireWise accepts UTF-8 CSV files with these eight required columns:

| Column | Accepted values |
|---|---|
| `id` | A non-empty, unique rule identifier. Leading/trailing spaces are trimmed with a warning. |
| `src_zone` | A non-empty source-zone name. |
| `dst_zone` | A non-empty destination-zone name. |
| `src_ip` | `any` or `*`, an IPv4/IPv6 address or CIDR network, or a semicolon-separated list of them. |
| `dst_ip` | `any` or `*`, an IPv4/IPv6 address or CIDR network, or a semicolon-separated list of them. |
| `service` | `any`/`all`, `icmp`, `icmpv6`, bare `tcp`/`udp`, a supported service alias, or a TCP/UDP port or range. Same-protocol lists may use `;`, `|`, or `,`. Quote comma-separated lists in CSV. |
| `action` | Permit: `permit`, `allow`, `accept`. Deny: `deny`, `block`, `drop`, `reject`. |
| `log` | True: `true`, `yes`, `1`, `on`, `enabled`. False: `false`, `no`, `0`, `off`, `disabled`. |

Supported service aliases:

| Alias | Protocol/port |
|---|---|
| `http`, `https`, `ssh`, `rdp` | TCP/80, TCP/443, TCP/22, TCP/3389 |
| `dns`, `ntp`, `snmp`, `syslog` | UDP/53, UDP/123, UDP/161, UDP/514 |
| `ftp`, `smtp`, `smtps`, `submission` | TCP/21, TCP/25, TCP/465, TCP/587 |
| `imap`, `imaps`, `pop3`, `pop3s` | TCP/143, TCP/993, TCP/110, TCP/995 |
| `mysql`, `postgres`, `mssql` | TCP/3306, TCP/5432, TCP/1433 |
| `ldap`, `ldaps`, `smb`, `telnet` | TCP/389, TCP/636, TCP/445, TCP/23 |

`tcp` and `udp` without a port match all ports for that protocol. Network entries
with host bits set are normalized to their network address and produce a warning.
Use `any` instead of a `/0` network to avoid a warning. A service list must use a
single protocol; split mixed TCP/UDP services into separate rows.

## Examples

Each example is a complete data row in the required column order:

```csv
r001,Internet,Web,203.0.113.0/24,10.10.0.0/24,https,permit,yes
r002,Staff,Database,10.20.0.0/16,10.30.0.0/24,"tcp/5432;tcp/6432",permit,true
r003,Guest,Internet,any,any,dns,permit,no
r004,Web,Database,10.10.0.0/24,10.30.0.0/24,tcp,deny,enabled
r005,Management,Network,192.0.2.10,192.0.2.0/24,icmp,allow,1
```

The double quotes around the second service list are required because commas
separate CSV columns.

## Common errors

- **Missing required columns or values:** include all eight headers and a value
  for each field in every rule row.
- **Duplicate or blank IDs:** every rule needs a unique non-empty `id`.
- **Invalid networks:** use valid IP addresses/CIDR notation; separate multiple
  networks with semicolons.
- **Host bits set:** `10.0.0.5/24` normalizes to `10.0.0.0/24`; check the
  displayed data warning to confirm this matches your intent.
- **Invalid port range:** the start must not exceed the end, and ports must be
  between 0 and 65535.
- **Mixed protocols in one service field:** split the entry into one rule row
  per protocol.
- **Unquoted comma-separated service list:** quote values such as
  `"tcp/80,443"` so the CSV reader treats them as one cell.
- **File too large or too many rules:** uploads are limited to 5,000,000 bytes
  and 5,000 rule rows.

See [`scripts/convert_example.py`](../scripts/convert_example.py) for a small
template for converting a mapped vendor-style CSV export.
