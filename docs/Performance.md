# Docker Performance and Soak Tests

OxiBelt includes a Docker-based performance harness for repeatable proxy smoke checks, benchmark evidence, and longer soak runs. It runs after the Docker integration matrix in CI and uses an isolated Docker network so OxiBelt, nginx, Caddy, the upstream server, and the load generator see the same container-to-container path.

## Running Locally

Build or provide an OxiBelt image, then run:

```sh
tests/scripts/run-proxy-performance.sh --profile smoke --comparators oxibelt,nginx,caddy
```

Profiles:

- `smoke`: short HTTP/1.1 keep-alive, HTTP/2, mandatory OxiBelt/Caddy HTTP/3, optional nginx HTTP/3 where available, TLS handshake sanity, and a short OxiBelt soak.
- `benchmark`: longer comparator runs plus OxiBelt WAF, CRS, cache, and stress scenarios.
- `soak`: long OxiBelt-focused concurrency presets and stress scenarios. This is intended for manual or scheduled runs, not every pull request.

Useful environment overrides:

```sh
OXIBELT_DOCKER_IMAGE=oxibelt:alpine-musl-amd64
OXIBELT_NGINX_IMAGE=nginx:mainline-alpine
OXIBELT_CADDY_IMAGE=caddy:2-alpine
OXIBELT_PERF_DURATION_SECONDS=30
OXIBELT_PERF_WARMUP_SECONDS=5
OXIBELT_PERF_CONCURRENCY=64
OXIBELT_PERF_SOAK_SECONDS=300
OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION=1
OXIBELT_PERF_TCP_BASELINE_MAX_P50_MS=20
OXIBELT_PERF_TCP_BASELINE_MAX_P99_MS=35
OXIBELT_TEST_ARTIFACT_DIR=/tmp/oxibelt-performance
```

`OXIBELT_PERF_OXIBELT_BASELINE_SCENARIO` is reserved for test fixtures that intentionally replace the baseline OxiBelt config. Normal local and CI performance runs should leave it unset.

In GitHub Actions, `workflow_dispatch` also accepts `performance_iterations`, which defaults to `5`. Reduce it for long manual `benchmark` or `soak` runs when the default repeated sampling would exceed the job budget.

## Artifacts

The runner writes:

- `summary.md`: compact Markdown table for human review.
- `results.json`: machine-readable results from the Rust probe.
- `docker-stats.jsonl`: sampled container CPU, memory, network, and block I/O from `docker stats`.
- `logs/`: per-container logs.
- `probe-logs/`: stdout and stderr captured from each probe scenario.
- `configs/`: generated effective proxy configs and TLS material used for the run.

CI runs the `docker-performance` job as five parallel `ubuntu-latest` shards. Each shard uploads one artifact named `oxibelt-docker-performance-<profile>-shard-<n>` and stores repeated samples under `run-1/` through `run-5/` by default. The workflow keeps running later iterations in the same shard after one iteration fails, then fails the job at the end with the failed iteration list so artifacts stay complete. Failed runs also keep the same files when `OXIBELT_TEST_ARTIFACT_DIR` is set.

## Interpreting Results

CI thresholds are sanity gates, not competitive claims. The job fails when the probe produces no traffic, sees handshake request errors, crosses the configured p99 latency ceiling, or sees load request errors above `OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION`. The default load budget is `1`, which permits at most one load transport error per million completed requests so noisy shared runners do not fail a long smoke soak after millions of successful responses. Set it to `0` to restore strict no-error load gating. `results.json` includes a bounded `error_samples` list for request, handshake, and stress errors, while `probe-logs/` keeps the surrounding probe stdout and stderr. OxiBelt and Caddy HTTP/3 are mandatory gates: if their functional QUIC readiness probe fails, the job fails instead of recording a skipped row. It also applies a narrower OxiBelt H1/H2 baseline latency-floor gate after the baseline HTTP/1.1, HTTP/2, and HTTP/3 rows are collected; override `OXIBELT_PERF_TCP_BASELINE_MAX_P50_MS` and `OXIBELT_PERF_TCP_BASELINE_MAX_P99_MS` when intentionally running on slower or noisier hosts. Noisy shared runners can move RPS and tail latency substantially, so compare trends across repeated runs and shards and inspect `docker-stats.jsonl` before treating a single result as a regression.

nginx and Caddy are measured as common reverse-proxy baselines only. OxiBelt-only behavior such as WAF, CRS compatibility, cache policy, and stress scenarios is measured separately. nginx HTTP/3 is included only when the selected image reports `--with-http_v3_module`; otherwise the HTTP/3 comparator row is recorded as skipped. If nginx reports HTTP/3 support but the functional QUIC probe cannot complete, that comparator row is also skipped because nginx HTTP/3 availability is image-dependent. Caddy is configured with its documented `h1 h2 h3` server protocol support and is treated as a mandatory HTTP/3 comparator.

The performance fixtures raise generic connection and per-connection request caps so benchmark and soak profiles measure proxy throughput instead of exercising OxiBelt's or nginx's default limit-enforcement safeguards.

References:

- Caddy server protocols: https://caddyserver.com/docs/caddyfile/options
- Caddy `reverse_proxy`: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy
- nginx HTTP/3 module: https://nginx.org/en/docs/http/ngx_http_v3_module.html
- nginx QUIC and HTTP/3: https://nginx.org/en/docs/quic.html
