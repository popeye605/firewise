# FireWise

FireWise is an educational firewall-rule health checker. It uses sample or
user-provided rule lists to explain common policy hygiene issues and recommend
reviewable improvements. It is for defensive learning and does not apply
firewall changes.

## CSV format

The required CSV columns are `id`, `src_zone`, `dst_zone`, `src_ip`, `dst_ip`,
`service`, `action`, and `log`. Addresses accept IPv4/IPv6 networks or `any`;
multiple addresses can be separated with semicolons. Services accept `any`,
`icmp`, `icmpv6`, bare `tcp` or `udp` (all ports), or `tcp/PORT[-END]` and
`udp/PORT[-END]`. Named aliases include `http`, `https`, `ssh`, `dns`, `rdp`,
`ntp`, `ftp`, `smtp`, `smtps`, `submission`, `imap`, `imaps`, `pop3`, `pop3s`,
`mysql`, `postgres`, `mssql`, `ldap`, `ldaps`, `smb`, `telnet`, `snmp`, and
`syslog`. Same-protocol service lists may use semicolons or pipes; quote
comma-separated lists in CSV, for example `"tcp/80,443"`. A service list cannot
mix protocols; use separate rule rows. Actions accept permit/allow/accept and
deny/block/drop/reject. Logging must be explicitly enabled or disabled.

## Phase 1: models and loading

Firewall rules are normalized into immutable, typed models. The loader validates
the CSV header and every value. `load_rules_with_warnings()` reports when host
bits were normalized, a `/0` network was written instead of `any`, or a rule ID
was trimmed; `load_rules()` keeps its original rules-only return value.
`load_demo_rules()` finds the bundled sample relative to the loader module rather
than the current working directory.

## Phases 2-3: findings and health score

`analyze_rules()` reports Any-Any rules, rules shadowed by earlier rules (also
when a sound union of same-service rules covers a target), duplicate
match-and-action rules, unlogged permits, and permits from configured untrusted
zones to trusted zones. Zone classifications use conventional defaults for the
demo and should be customized for real networks.

`calculate_health_score()` assigns 10, 5, and 2 points to high, medium, and low
findings. Combined penalties are capped at 10 per affected rule, so overlapping
findings cannot subtract more than the maximum risk assigned to one rule. The
score is `round(100 * (1 - total_penalty / (rule_count * 10)))`, constrained to
0-100. An empty rule list is rejected.

## Phase 4: attack paths

`build_zone_graph()` creates a directed NetworkX multigraph with one edge per
reachable permit rule by default; permits fully covered by earlier rules are
omitted. Set `respect_order=False` to include all permits. Denies do not create
paths. Riskier allows have lower positive cost: the base risk is increased for
Any-Any rules, unlogged permits, and default untrusted-to-trusted zone pairs,
then mapped to `10 / (1 + risk)`.

`astar_search()` implements A* directly. Its heuristic is the minimum edge cost
times the fewest remaining zone hops, which is an admissible lower bound.
`breadth_first_search()` independently implements BFS and returns a fewest-hop
route; it does not minimize risk cost. Both results report the visited-node
count. The conventional zone-name defaults should be adapted to each network.

## Phase 5: genetic optimizer

`optimize_rules()` evolves a chromosome of ordered rule IDs independently per
source/destination zone pair. Tournament selection, membership-and-order
crossover, remove/add/swap mutation, and elitism are implemented in Python.
Fitness favors fewer rules and lower permit risk, with a 100,000-point penalty
for every changed boundary-packet decision.

The candidate is checked against deterministic network/port-boundary packets and
exactly 1,000 seeded random packets by default. Comparisons use first-match
allow/deny behavior and include implicit deny. If any tested decision changes,
the candidate is rejected and the original policy is returned. The check is
strong evidence, not a formal proof for every possible packet. Rules marked
`not_analyzed` are refused by the optimizer rather than approximated.
By default, logged deny rules are forced to stay in every recommendation; set
`keep_deny_rules=True` to preserve all deny rules. Removed deny rules are
reported because removing them also removes their logging.

Optimized rules are recommendations only; FireWise never applies them.

## Run on Windows

From the project root, create a virtual environment, install the project
dependencies, and start the Streamlit app:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the URL printed by Streamlit (normally `http://localhost:8501`). To install
the optional test dependency as well, use
`.\.venv\Scripts\python.exe -m pip install -e ".[test]"`.

## Phase 7: HTML report

The Report tab generates a standalone HTML download with the policy source,
health score, findings by type, data warnings, each finding's explanation and
suggested fix, any A*/BFS path comparison, and any optimizer verification
recorded in the session. User-controlled values are HTML-escaped, and the report
has no external assets or network dependencies.

Run tests from the project root:

```powershell
python -m pytest -q
```
