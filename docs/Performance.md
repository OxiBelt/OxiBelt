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

Serving type filters:

- `all`: run the legacy combined local set.
- `reverse-proxy`: common OxiBelt, nginx, and Caddy H1/H2/H3 reverse-proxy rows plus the OxiBelt TLS handshake and TLS resumption-mode diagnostic rows.
- `static-files`: static file rows for `/static/1k.bin`, `/static/16k.bin`, and `/static/1m.bin` according to the selected profile.
- `oxibelt-features`: OxiBelt-only WAF, CRS, and cache rows.
- `oxibelt-soak-stress`: OxiBelt smoke soak, benchmark stress, or soak concurrency rows according to the selected profile.
- `accept-multipliers`: OxiBelt-only comparison of `runtime.worker_multipliers.accept = 0.5` and `1.0` across `h1-keepalive`, `h2`, `h3`, `static-16k-h1c`, `tls-handshake-h2`, `waf-enforcing`, and `crs-enforcing`.

Useful environment overrides:

```sh
OXIBELT_DOCKER_IMAGE=oxibelt:alpine-musl-amd64
OXIBELT_NGINX_IMAGE=nginx:mainline-alpine
OXIBELT_CADDY_IMAGE=caddy:2-alpine
OXIBELT_PERF_DURATION_SECONDS=30
OXIBELT_PERF_WARMUP_SECONDS=5
OXIBELT_PERF_CONCURRENCY=64
OXIBELT_PERF_SOAK_SECONDS=300
OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION=100
OXIBELT_PERF_TCP_BASELINE_MAX_P50_MS=20
OXIBELT_PERF_TCP_BASELINE_MAX_P99_MS=35
OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO=0.85
OXIBELT_PERF_WAF_ENFORCING_MIN_RPS=11000
OXIBELT_PERF_CRS_ENFORCING_MIN_RPS=9000
OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO=1.20
OXIBELT_PERF_REGRESSION_GATE_MODE=fail
OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO=baseline-accept-1
OXIBELT_TEST_ARTIFACT_DIR=/tmp/oxibelt-performance
```

`OXIBELT_PERF_OXIBELT_BASELINE_SCENARIO` is reserved for test fixtures that intentionally replace the baseline OxiBelt config. Normal local and CI performance runs should leave it unset. The default baseline follows the release-oriented auto-worker profile: runtime and HTTP/3 socket workers resolve from Rust `available_parallelism()` with `1.0` multipliers, TCP accept workers resolve with the conservative `0.5` multiplier, TCP/UDP `SO_REUSEPORT` is enabled, backlog is `8192`, and explicit upstream idle pool caps, HTTP/2 builder tuning, and QUIC socket buffers are configured. Configs that explicitly set `runtime.worker_multipliers.accept = 1.0` keep the previous CPU-count accept-worker profile. `OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO` defaults to `baseline-accept-1` so the OxiBelt `tls-handshake-h2` row uses a handshake-heavy fixture without changing the steady-state baseline.

For cold TLS handshake investigations where post-quantum hybrid key exchange cost should be isolated, set `OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO=baseline-classical-kx`. That fixture keeps the handshake-heavy accept-worker profile and sets `tls.key_exchange_groups = ["x25519", "secp256r1", "secp384r1"]`.

The `oxibelt-tls-handshake-h2` row keeps a fresh client TLS configuration per connection, so it remains a cold-handshake measurement. The companion `oxibelt-tls-handshake-h2-resumption-diagnostic` row reuses client TLS state per probe worker and briefly observes post-handshake TLS records so `results.json` can show whether tickets were received and whether later handshakes resumed. Its handshake result includes `client_resumption`, `post_handshake_observe_ms`, `handshake_kinds`, `tls13_tickets_received`, and `negotiated_key_exchange_groups` fields. Use that non-gating row to diagnose stateful resumption behavior; use the fresh row for cold-handshake throughput comparisons.

The OxiBelt-only resumption-mode handshake rows also use fresh client TLS state so they isolate server-side ticket issuance and storage overhead without measuring resumed handshakes. Smoke and benchmark reverse-proxy runs record `oxibelt-tls-handshake-h2-resumption-off`, `oxibelt-tls-handshake-h2-resumption-stateless-tickets-2`, `oxibelt-tls-handshake-h2-resumption-stateful-tickets-1`, and `oxibelt-tls-handshake-h2-resumption-stateful-tickets-2`. These rows include the same handshake fields plus a `server_session_storage` delta with stateful `StoresServerSessions` `put_count`, `get_count`, `take_count`, `lock_wait_ns`, and `put_duration_ns` counters. Per-run summaries and aggregate reports retain p95 and p99 latency columns for these rows.

The plain reverse-proxy fast path and plaintext static sendfile path are allowed to stay active for low-cost response metadata work such as configured security response headers and request-wide system access logs. Routes with `compression = "off"` can also use the plain reverse-proxy fast path even when global compression is enabled. Body-transforming compression, cache lookup/fill, WAF inspection that needs body bytes, dynamic policy, rate limiting, upgrades, CONNECT, upstream pools, upstream HTTP/3, PROXY protocol egress, and buffering remain on the general proxy path so HTTP and security semantics stay unchanged.

OxiRule payload inspection is bounded by `waf.limits.max_body_inspection_bytes`, which defaults to `1048576` bytes. Rules that read `Request.Body`, `Response.Body`, or stream payload text/content helpers inspect only that captured prefix before replaying or forwarding the remaining bytes. Repeated text-oriented helpers such as `Body.Text`, `contains`, `matches`, `containsAny`, `matchesAny`, and `scan` share one decoded text view per request, response, or stream evaluation, and repeated scans of the same pattern set reuse the same result. Contains pattern sets are compiled into a multi-pattern scanner while preserving configured pattern priority, and large text scans run on Tokio's blocking worker pool when OxiBelt is executing on the multi-thread runtime. These optimizations sit above the common HTTP body abstraction, so HTTP/1.1, HTTP/2, and HTTP/3 request bodies all use the same optimized WAF scan path after the bounded prefix has been captured.

The baseline performance fixture also includes `/static/1k.bin`, `/static/16k.bin`, and `/static/1m.bin` static file scenarios. OxiBelt enables `proxy.static_files.sendfile = "auto"` and the opt-in static hot-object cache for that fixture: plaintext HTTP/1.1 static rows are labeled `h1c` and can exercise the guarded Linux sendfile path or hot small-object path, while TLS H1/H2/H3 static rows measure the optimized streaming fallback. nginx is configured with `sendfile on`, and Caddy uses `file_server`, so benchmark profile static rows compare the same static file sizes across all comparators.

In GitHub Actions, `workflow_dispatch` also accepts `performance_iterations`, which defaults to `5`. Reduce it for long manual `benchmark` or `soak` runs when the default repeated sampling would exceed the job budget.

## Artifacts

The runner writes:

- `summary.md`: compact Markdown table for human review.
- `results.json`: machine-readable results from the Rust probe.
- `docker-stats.jsonl`: sampled container CPU, memory, network, and block I/O from `docker stats`.
- `logs/`: per-container logs.
- `probe-logs/`: stdout and stderr captured from each probe scenario.
- `configs/`: generated effective proxy configs and TLS material used for the run.

The runner generates one-run TLS material and a one-run 64-byte QUIC host key under `configs/*/cert/`. The performance baseline enables `quic.host_key_file` only against that generated key so Retry/stateless reset token behavior is stable within the run without baking shared key material into fixtures or images.

CI runs the `docker-performance` job as five parallel `ubuntu-latest` shards for each serving type. Push and pull-request smoke runs intentionally collect all serving-type groups so reverse-proxy, static-file, OxiBelt feature, soak/stress, and accept multiplier evidence land in separate artifacts. Each shard uploads one artifact named `oxibelt-docker-performance-<profile>-<serving_type>-shard-<n>` and stores repeated samples under `run-1/` through `run-5/` by default. The workflow keeps running later iterations in the same shard after one iteration fails, then fails the job at the end with the failed iteration list so artifacts stay complete. In CI, targeted RPS and p99 regression gates run with `OXIBELT_PERF_REGRESSION_GATE_MODE=warn`, so noisy single-iteration threshold misses are recorded while the summary job makes the final median-based decision. Failed runs also keep the same files when `OXIBELT_TEST_ARTIFACT_DIR` is set.

After the sharded jobs finish, CI runs a `Docker performance summary` job that downloads all `oxibelt-docker-performance-<profile>-*` artifacts from the same workflow run and writes an aggregate artifact named `oxibelt-docker-performance-<profile>-comparison`. That artifact contains:

- `performance-comparison.md`: a run-summary-friendly comparison report.
- `performance-comparison.json`: a stable machine-readable schema for follow-up analysis.

The comparison job also appends `performance-comparison.md` to the GitHub Actions run summary and fails when `performance-comparison.json` reports median regression gate violations. If some matrix artifacts are missing because a shard failed before upload or a dependency skipped the performance job, the aggregate report is still generated from the artifacts that exist and records the missing paths in the Warnings section.

To reproduce the aggregation locally after downloading artifacts:

```sh
cargo run --quiet --locked -p oxibelt --bin oxibelt-performance-aggregate -- \
  --input-dir <downloaded-artifacts-dir> \
  --output-dir <report-dir>
```

## Interpreting Results

CI thresholds are sanity gates, not competitive claims. The job fails when the probe produces no traffic, sees handshake request errors, crosses the configured p99 latency ceiling, or sees load request errors above `OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION`. The default load budget is `100`, which permits at most 100 load transport errors per million completed requests so noisy shared runners do not fail a long smoke soak after millions of successful responses. Set it to `0` to restore strict no-error load gating. `results.json` includes a bounded `error_samples` list for request, handshake, and stress errors, while `probe-logs/` keeps the surrounding probe stdout and stderr. OxiBelt and Caddy HTTP/3 are mandatory gates: if their functional QUIC readiness probe fails, the job fails instead of recording a skipped row. It also applies a narrower OxiBelt H1/H2 baseline latency-floor gate after the baseline HTTP/1.1, HTTP/2, and HTTP/3 rows are collected; override `OXIBELT_PERF_TCP_BASELINE_MAX_P50_MS` and `OXIBELT_PERF_TCP_BASELINE_MAX_P99_MS` when intentionally running on slower or noisier hosts. Noisy shared runners can move RPS and tail latency substantially, so compare trends across repeated runs and shards and inspect `docker-stats.jsonl` before treating a single result as a regression.

Targeted regression gates pin known-sensitive paths. The static file group checks whether `oxibelt-static-16k-h1c` falls below `OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO` of the matching Caddy row. The `oxibelt-features` group checks whether WAF enforcing RPS is below `OXIBELT_PERF_WAF_ENFORCING_MIN_RPS`, CRS enforcing RPS is below `OXIBELT_PERF_CRS_ENFORCING_MIN_RPS`, or either WAF/CRS enforcing p99 exceeds its monitor p99 by more than `OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO`. Local runs use `OXIBELT_PERF_REGRESSION_GATE_MODE=fail` by default and fail as soon as one of these targeted gates is crossed. CI sets that mode to `warn` for shard iterations, then the aggregate summary evaluates the same threshold variables against median RPS and median p99 ratios across the downloaded samples.

The comparison report is a median-based reference over the repeated shard and iteration samples, not a standalone performance claim. It normalizes labels by comparator prefix, so `oxibelt-h1-keepalive`, `nginx-h1-keepalive`, and `caddy-h1-keepalive` are compared as the same `h1-keepalive` scenario. Ratios use median RPS:

```text
oxibelt_vs_nginx = median_rps(oxibelt scenario) / median_rps(nginx same scenario)
oxibelt_vs_caddy = median_rps(oxibelt scenario) / median_rps(caddy same scenario)
```

The report displays both percent and multiplier forms, such as `95.0% of nginx` and `0.95x nginx`. If a comparator row is skipped, missing, or has zero median RPS, the ratio is omitted and the reason is listed under skipped or missing comparator rows.

The accept multiplier comparison report keeps `oxibelt-accept-0_5-*` and `oxibelt-accept-1_0-*` rows out of the nginx/Caddy tables and compares them as OxiBelt-only pairs. A lower accept multiplier can improve steady-state rows by reducing accept-loop and `SO_REUSEPORT` contention, while `accept = 1.0` can recover throughput for handshake-heavy workloads that create new TCP/TLS connections continuously. Treat this as a profile tradeoff: use the default `0.5` baseline for steady-state comparisons, and use the `baseline-accept-1` fixture or `OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO` for handshake-heavy investigations.

nginx and Caddy are measured as common reverse-proxy and static-file baselines only. OxiBelt-only behavior such as WAF, CRS compatibility, cache policy, TLS handshake rows without matching comparator rows, and stress scenarios is measured separately. These OxiBelt-only scenarios are not mixed into nginx/Caddy ratios because they do not measure the same behavior. nginx HTTP/3 is included only when the selected image reports `--with-http_v3_module`; otherwise the HTTP/3 comparator row is recorded as skipped. If nginx reports HTTP/3 support but the functional QUIC probe cannot complete, that comparator row is also skipped because nginx HTTP/3 availability is image-dependent. Caddy is configured with its documented `h1 h2 h3` server protocol support and is treated as a mandatory HTTP/3 comparator.

The performance fixtures raise generic connection and per-connection request caps so benchmark and soak profiles measure proxy throughput instead of exercising OxiBelt's or nginx's default limit-enforcement safeguards. Release builds use thin LTO, one codegen unit, and stripped debuginfo; `panic = "abort"` is intentionally not set so postmortem behavior stays conservative.

References:

- Caddy server protocols: https://caddyserver.com/docs/caddyfile/options
- Caddy `reverse_proxy`: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy
- nginx HTTP/3 module: https://nginx.org/en/docs/http/ngx_http_v3_module.html
- nginx QUIC and HTTP/3: https://nginx.org/en/docs/quic.html
