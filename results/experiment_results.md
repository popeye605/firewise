# FireWise experiment results

Seed: `2026`. Optimizer random packet budget: `200`.

| Policy | Rules | Findings | Score | A* nodes | BFS nodes | Optimizer rules | Permit risk | Packets tested |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| demo_rules | 40 | 23 | 74 | 78 | 115 | 40 → 30 | 79 → 67 | 3680 |
| astar_demo | 4 | 6 | 25 | 16 | 16 | 4 → 4 | 40 → 40 | 1295 |
| stress_rules | 21 | 20 | 81 | 2 | 2 | 21 → 1 | 21 → 1 | 275 |
