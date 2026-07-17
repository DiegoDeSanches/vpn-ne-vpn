# Performance and soak tests

Lab-only latency, throughput, memory, flow-control, rotation, and long-running
session tests are specified in `docs/integration-plan.md`. Raw user browsing data is
never a performance data source.

`benchmark.py` захватывает только Mock Tor harness baseline; `thresholds.json`
содержит environment-relative regression gates, не выдуманные product SLO.
`compare_baseline.py` запрещает сравнение разных fingerprints и baseline менее 30
samples. Battery измеряется только физическим device power harness.
