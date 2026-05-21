# OxiBelt Docker Performance (benchmark)

- Run id: `1779350497-77556-7989`
- Serving type: `oxibelt-features`
- Comparators: `oxibelt`
- OxiBelt baseline fixture: `baseline`
- OxiBelt handshake fixture: `baseline-accept-1`
- Duration: `30s`
- Warmup: `5s`
- Concurrency: `64`

| Scenario | Type | Protocol | Result | Notes |
| --- | --- | --- | --- | --- |
| `oxibelt-waf-monitor` | `load` | `h2` | 1310801 req, 43693.37/sec, p95 2.41 ms, p99 2.98 ms | errors=0 |
| `oxibelt-waf-enforcing` | `load` | `h2` | 1272868 req, 42428.93/sec, p95 2.56 ms, p99 3.15 ms | errors=0 |
| `oxibelt-crs-monitor` | `load` | `h2` | 1155853 req, 38528.43/sec, p95 2.64 ms, p99 3.27 ms | errors=0 |
| `oxibelt-crs-enforcing` | `load` | `h2` | 1173498 req, 39116.60/sec, p95 2.59 ms, p99 3.18 ms | errors=0 |
| `oxibelt-cache-noncacheable-miss` | `load` | `h2` | 483924 req, 16130.80/sec, p95 5.80 ms, p99 6.78 ms | errors=0 |
| `oxibelt-cache-cold-fill` | `load` | `h2` | 244580 req, 8152.67/sec, p95 11.48 ms, p99 13.18 ms | errors=0 |
| `oxibelt-cache-hit` | `load` | `h2` | 861742 req, 28724.73/sec, p95 3.65 ms, p99 4.39 ms | errors=0 |
| `oxibelt-cache-revalidate` | `load` | `h2` | 801543 req, 26718.10/sec, p95 3.89 ms, p99 4.69 ms | errors=0 |
| `oxibelt-cache-stale` | `load` | `h2` | 881419 req, 29380.63/sec, p95 3.57 ms, p99 4.33 ms | errors=0 |

Artifacts:

- results.json
- docker-stats.jsonl
- logs/
- probe-logs/
- configs/
