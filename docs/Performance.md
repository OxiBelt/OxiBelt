# Docker Performance and Soak Tests

OxiBelt includes a Docker-based performance harness for repeatable proxy smoke checks, benchmark evidence, and longer soak runs. It runs after the Docker integration matrix in CI and uses an isolated Docker network so OxiBelt, nginx, Caddy, the upstream server, and the load generator see the same container-to-container path.

## Running Locally

Build or provide an OxiBelt image, then run:

```sh
tests/scripts/run-proxy-performance.sh --profile smoke --comparators oxibelt,nginx,caddy
```

Profiles:

- `smoke`: short HTTP/1.1 keep-alive, HTTP/2, HTTP/3 where available, TLS handshake sanity, and a short OxiBelt soak.
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
OXIBELT_TEST_ARTIFACT_DIR=/tmp/oxibelt-performance
```

## Artifacts

The runner writes:

- `summary.md`: compact Markdown table for human review.
- `results.json`: machine-readable results from the Rust probe.
- `docker-stats.jsonl`: sampled container CPU, memory, network, and block I/O from `docker stats`.
- `logs/`: per-container logs.
- `configs/`: generated effective proxy configs and TLS material used for the run.

CI uploads these artifacts from the `docker-performance` job. Failed runs also keep the same files when `OXIBELT_TEST_ARTIFACT_DIR` is set.

## Interpreting Results

CI thresholds are sanity gates, not competitive claims. The job fails when the probe cannot complete requests, sees request errors in load/handshake scenarios, produces no traffic, or crosses the configured p99 latency ceiling. Noisy shared runners can move RPS and tail latency substantially, so compare trends across repeated runs and inspect `docker-stats.jsonl` before treating a single result as a regression.

nginx and Caddy are measured as common reverse-proxy baselines only. OxiBelt-only behavior such as WAF, CRS compatibility, cache policy, and stress scenarios is measured separately. nginx HTTP/3 is included only when the selected image reports `--with-http_v3_module`; otherwise the HTTP/3 comparator row is recorded as skipped. Caddy is configured with its documented `h1 h2 h3` server protocol support.

The performance fixtures raise generic connection and per-connection request caps so benchmark and soak profiles measure proxy throughput instead of exercising OxiBelt's default limit-enforcement safeguards.

References:

- Caddy server protocols: https://caddyserver.com/docs/caddyfile/options
- Caddy `reverse_proxy`: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy
- nginx HTTP/3 module: https://nginx.org/en/docs/http/ngx_http_v3_module.html
- nginx QUIC and HTTP/3: https://nginx.org/en/docs/quic.html
