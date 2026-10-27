# FireWise

FireWise is an educational, defensive firewall-rule auditing app. Upload a CSV
policy to inspect common rule hygiene issues, compare zone paths, and produce a
behavior-tested optimization recommendation.

![FireWise screenshot placeholder](docs/screenshot.png)

## Install and run

Use Python 3.11 or newer from the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local URL printed by Streamlit, usually `http://localhost:8501`.

## CSV input

Policies are loaded from CSV with eight required columns. See the
[CSV format guide](docs/CSV_FORMAT.md) for accepted networks, services,
actions, logging values, examples, and common errors. A
[vendor-style conversion template](scripts/convert_example.py) shows how to
map a simple CSV export into FireWise format.

The app also includes three bundled samples: `demo_rules`, `astar_demo`, and
`stress_rules`.

## Features

- Explainable findings for broad, duplicate, shadowed, unlogged, and
  untrusted-to-trusted rules.
- A customizable zone-trust editor and import/export JSON.
- A network graph with first-match reachability filtering.
- A* minimum-risk paths and BFS fewest-hop paths.
- A genetic algorithm (GA) that recommends smaller ordered policies and
  checks packet decisions before offering the result.
- Downloadable CSV recommendations and self-contained HTML reports.

Zone trust can be imported/exported as JSON; names are compared
case-insensitively, and a zone cannot be both trusted and untrusted:

```json
{
  "untrusted": ["internet", "guest"],
  "trusted": ["database", "internal"]
}
```

### How the analysis works

- **A\*** uses positive permit-risk edge costs and an admissible hop-based
  heuristic to find a lowest-cost zone route. **BFS** independently finds a
  route with the fewest zone hops.
- **GA** evolves ordered rule subsets independently for each source/destination
  zone pair. It favors smaller, lower-risk candidates, while keeping configured
  deny rules and checking that allow/deny decisions do not change for generated
  boundary and seeded random packets.
- **Constraint checks** compare normalized source and destination network
  intervals and service port ranges. Shadow analysis reports full coverage,
  including sound unions of earlier rules, and avoids combining independent
  source/destination coverage into false positives.

## Results on bundled demo data

Measured with the default zone-trust settings, the demo policy has **40 rules,
23 findings, and a health score of 74/100**. Moving `web` from trusted to neutral
reduces trust-boundary findings and raises the score from the previous 70/100 to
74/100. The baseline default classification
includes Internet as untrusted and Database as trusted; the `web` zone is now
neutral. Across all reachable zone pairs, the measured A*/BFS explored-node
totals are 78/115. The fixed-seed optimizer recommended 30 rules from 40, lowered
permit-risk points from 79 to 67, and compared 3,680 packets. The optimizer
recommendation is review-only and is measured separately from the policy health
score.

Run `python experiments.py` to reproduce the measurements for all three CSV
samples. The fixed-seed results are written to
[`results/experiment_results.md`](results/experiment_results.md).

## Limitations

- CSV input only; FireWise does not connect to a firewall or apply changes.
- NAT, schedules, FQDN objects, and other vendor-specific policy semantics are
  not modeled.
- Optimizer behavior verification is sampled, not a formal proof for every
  possible packet.
- For a zone-pair group larger than 200 rules, the optimizer caps packet
  verification at 100 packets and its search at 8 candidates × 6 generations.
- Default zone trust is name-based and may not match your network; configure it
  for your environment before interpreting trust-boundary findings.
- Uploads are limited to 5 MB and 5,000 firewall rules.

## Security

Use only sanitized data; uploads are processed locally. Do not upload secrets,
credentials, or unredacted sensitive network details.

Recommendations are for review only; FireWise never changes a real firewall.

## Tests

```powershell
python -m pytest -q
```
