# Docker Performance and Soak Tests

OxiBelt includes a Docker-based performance harness for repeatable proxy smoke checks, benchmark evidence, and longer soak runs. It runs after the Docker integration matrix in CI and uses an isolated Docker network so OxiBelt, nginx, Caddy, the upstream server, and the load generator see the same container-to-container path.

## Running Locally

Build or provide an OxiBelt image, then run:

```sh
tests/scripts/run-proxy-performance.sh --profile smoke --comparators oxibelt,nginx,caddy
```

Profiles:

- `smoke`: short HTTP/1.1 keep-alive, HTTP/2, mandatory OxiBelt/Caddy HTTP/3, optional nginx HTTP/3 where available, cold TLS handshake comparison, and a short OxiBelt soak.
- `benchmark`: longer comparator runs, cold TLS handshake comparison, plus OxiBelt WAF, CRS, cache, and stress scenarios.
- `soak`: long OxiBelt-focused concurrency presets and stress scenarios. This is intended for manual or scheduled runs, not every pull request.

Serving type filters:

- `all`: run the legacy combined local set.
- `reverse-proxy`: common OxiBelt, nginx, and Caddy H1/H2/H3 reverse-proxy rows plus cold TLS handshake comparison rows and OxiBelt TLS resumption-mode diagnostic rows. The common `*-h2` reverse-proxy rows use a downstream HTTP/2 client and the default upstream protocol configured by each comparator fixture; for the OxiBelt baseline this is upstream HTTP/1.1 keep-alive. OxiBelt also records split rows for downstream H2 to upstream h2c and downstream H2 to upstream TLS H2 so downstream and upstream protocol costs can be separated.
- `static-files`: static file rows for `/static/1k.bin`, `/static/16k.bin`, and `/static/1m.bin` according to the selected profile.
- `oxibelt-features`: OxiBelt-only WAF, CRS, and cache rows.
- `oxibelt-soak-stress`: OxiBelt smoke soak, benchmark stress, or soak concurrency rows according to the selected profile.
- `accept-multipliers`: OxiBelt-only comparison of `runtime.worker_multipliers.accept = 0.5` and `1.0` across `h1-keepalive`, `h2`, `h3`, `static-16k-h1c`, `tls-handshake-h2`, `waf-enforcing`, and `crs-enforcing`.
- `remote-signer`: OxiBelt-only comparison of local private-key TLS and `[tls.remote_signer]` sidecar signing across downstream H1, H2, H3, and cold H2 TLS handshakes.
- `oxibelt-aggressive-long-run`: OxiBelt-only scheduled/manual long-run coverage. It splits `OXIBELT_PERF_SOAK_SECONDS` across H1, H2, and H3 steady soak rows, then runs slow POST, slow response, H2 stream churn, H2 `Content-Length: 0` plus DATA, and H3 `Content-Length: 0` plus DATA stress rows before checking OxiBelt RSS, FD, task, and thread drift.

Useful environment overrides:

```sh
OXIBELT_DOCKER_IMAGE=oxibelt:alpine-musl-amd64
OXIBELT_AMD64_TARGET_CPU=x86-64-v3
OXIBELT_NGINX_IMAGE=nginx:mainline-alpine
OXIBELT_NGINX_H3_MODE=auto
OXIBELT_CADDY_IMAGE=caddy:2-alpine
OXIBELT_PERF_DURATION_SECONDS=30
OXIBELT_PERF_WARMUP_SECONDS=5
OXIBELT_PERF_CONCURRENCY=64
OXIBELT_PERF_SOAK_SECONDS=300
OXIBELT_PERF_AGGRESSIVE_STRESS_SECONDS=180
OXIBELT_PERF_RESOURCE_MAX_MEMORY_DELTA_BYTES=268435456
OXIBELT_PERF_RESOURCE_MAX_FD_DELTA=256
OXIBELT_PERF_RESOURCE_MAX_TASK_DELTA=64
OXIBELT_PERF_RESOURCE_SETTLE_SECONDS=30
OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION=100
OXIBELT_PERF_TCP_BASELINE_MAX_P50_MS=25
OXIBELT_PERF_TCP_BASELINE_MAX_P99_MS=45
OXIBELT_PERF_H2_MIN_NGINX_RATIO=0.80
OXIBELT_PERF_H3_MIN_NGINX_RATIO=0.80
OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO=0.80
OXIBELT_PERF_STATIC_16K_H1C_MIN_NGINX_RATIO=0.90
OXIBELT_PERF_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO=0.90
OXIBELT_PERF_WAF_ENFORCING_MIN_RPS=10000
OXIBELT_PERF_CRS_ENFORCING_MIN_RPS=8000
OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO=1.30
OXIBELT_PERF_REGRESSION_GATE_MODE=fail
OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO=baseline-accept-1
OXIBELT_PERF_PROFILE_LABEL=oxibelt-h2
OXIBELT_PERF_PROFILE_FREQUENCY=99
OXIBELT_PERF_PROFILE_CALL_GRAPH=dwarf,8192
OXIBELT_TEST_ARTIFACT_DIR=/tmp/oxibelt-performance
```

CI builds three AMD64 Alpine musl image artifacts for `x86-64-v2`, `x86-64-v3`, and `x86-64-v4`. The default `oxibelt-alpine-musl-amd64-image` artifact and `oxibelt:alpine-musl-amd64` tag target `x86-64-v3`; the alternate artifact names are `oxibelt-alpine-musl-amd64v2-image` and `oxibelt-alpine-musl-amd64v4-image`. Docker integration, remote signer, and browser WebDriver jobs use `tests/scripts/select-amd64-docker-image-artifact.sh auto` to load the newest artifact supported by the runner CPU.

Docker performance jobs run the `x86-64-v2` and `x86-64-v3` OxiBelt images sequentially in the same runner job for each shard and serving type. CI also builds target-specific Alpine nginx and Caddy comparator images for those same AMD64 ISA levels, so each target pass compares OxiBelt with nginx and Caddy binaries built for the matching target CPU. The nginx comparator is also built with GCC hardening flags for FORTIFY, stack protection, stack-clash protection, CET control-flow protection, PIE, full RELRO, immediate binding, and non-executable stack metadata; sanitizer instrumentation stays out of the comparator image so performance rows remain meaningful. Local runs still default to the official Alpine nginx (`nginx:mainline-alpine`) and Caddy (`caddy:2-alpine`) images unless `OXIBELT_NGINX_IMAGE` or `OXIBELT_CADDY_IMAGE` is set. The `x86-64-v4` image artifact is still built for compatibility checks, but it is excluded from the Docker performance target set. The matrix runs 20 shards per serving type with the configured iteration count, defaulting to five iterations per target per shard. The aggregate report keeps the existing regression gates and baseline delta comparison on the primary `x86-64-v3` target, then adds an AMD64 ISA comparison section that reports OxiBelt `x86-64-v2` median RPS and p99 deltas against `x86-64-v3`. A runner that does not expose a requested target's CPU features uploads an `unsupported-cpu.json` marker for that target instead of benchmark rows; the aggregate report lists those target shards and excludes them from expected-result warnings, statistics, and regression gates. The aggressive long-run job still requires `x86-64-v3` and fails immediately on an unsupported runner so the job can be manually rerun on a different runner.

`OXIBELT_PERF_OXIBELT_BASELINE_SCENARIO` is reserved for test fixtures that intentionally replace the baseline OxiBelt config. Normal local and CI performance runs should leave it unset. The default baseline follows the release-oriented auto-worker profile: runtime and HTTP/3 socket workers resolve from Rust `available_parallelism()` with `1.0` multipliers, TCP accept workers resolve with the conservative `0.5` multiplier, TCP/UDP `SO_REUSEPORT` is enabled, backlog is `8192`, and explicit upstream idle pool caps, HTTP/2 builder tuning, and QUIC socket buffers are configured. The baseline HTTP/2 fixture disables adaptive windows and uses `initial_stream_window_bytes = 1048576`, `initial_connection_window_bytes = 16777216`, and `max_frame_size_bytes = 65535` so CI measures the fixed-window performance baseline while product defaults remain unchanged. Configs that explicitly set `runtime.worker_multipliers.accept = 1.0` keep the previous CPU-count accept-worker profile. `OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO` defaults to `baseline-accept-1` so the OxiBelt `tls-handshake-h2` row uses a handshake-heavy fixture without changing the steady-state baseline.

For cold TLS handshake investigations where post-quantum hybrid key exchange cost should be isolated, set `OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO=baseline-classical-kx`. That fixture keeps the handshake-heavy accept-worker profile and sets `tls.key_exchange_groups = ["x25519", "secp256r1", "secp384r1"]`.

The `tls-handshake-h2` rows for OxiBelt, nginx, and Caddy keep a fresh client TLS configuration per connection, so they remain cold-handshake measurements. The companion `oxibelt-tls-handshake-h2-resumption-diagnostic` row reuses client TLS state per probe worker and briefly observes post-handshake TLS records so `results.json` can show whether tickets were received and whether later handshakes resumed. Its handshake result includes `client_resumption`, `post_handshake_observe_ms`, `handshake_kinds`, `tls13_tickets_received`, and `negotiated_key_exchange_groups` fields. Use that non-gating row to diagnose stateful resumption behavior; use the fresh rows for cold-handshake throughput comparisons.

The OxiBelt-only resumption-mode handshake rows also use fresh client TLS state so they isolate server-side ticket issuance and storage overhead without measuring resumed handshakes. Smoke and benchmark reverse-proxy runs record `oxibelt-tls-handshake-h2-resumption-off`, `oxibelt-tls-handshake-h2-resumption-stateless-tickets-2`, `oxibelt-tls-handshake-h2-resumption-stateful-tickets-1`, and `oxibelt-tls-handshake-h2-resumption-stateful-tickets-2`. These rows include the same handshake fields plus a `server_session_storage` delta with stateful `StoresServerSessions` `put_count`, `get_count`, `take_count`, `lock_wait_ns`, and `put_duration_ns` counters. Per-run summaries and aggregate reports retain p95 and p99 latency columns for these rows.

The `remote-signer` serving type starts `oxibelt-keysigner` from the same Docker image as a sidecar, shares only the Unix-socket directory with OxiBelt, and omits `privkey.pem` from the proxy container. Rows labeled `oxibelt-local-key-*` and `oxibelt-remote-signer-*` compare the same request paths with local signing versus IPC signing. Per-run `summary.md` and the aggregate `performance-comparison.md` report remote signer throughput as a percentage of local-key throughput, plus the p99 latency ratio. The aggregate report gates the cold H2 TLS handshake row with `OXIBELT_PERF_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO`; other remote signer rows remain descriptive evidence.

The plain reverse-proxy fast path and plaintext static sendfile path are allowed to stay active for low-cost response metadata work such as configured security response headers and request-wide system access logs. Routes with `compression = "off"` can also use the plain reverse-proxy fast path even when global compression is enabled. Body-transforming compression, cache lookup/fill, WAF inspection that needs body bytes, dynamic policy, rate limiting, upgrades, CONNECT, upstream pools, upstream HTTP/3, PROXY protocol egress, and buffering remain on the general proxy path so HTTP and security semantics stay unchanged. Benchmark reverse-proxy runs include an OxiBelt-only `oxibelt-h2-adaptive-window` row that keeps the same upstream HTTP/1.1 fixture but restores adaptive H2 windows as diagnostic evidence against the fixed-tuning baseline. This diagnostic row does not change the default product `proxy.http2` values or regression gates.

The OxiBelt cache feature rows separate non-cacheable misses from actual cold fills. `oxibelt-cache-noncacheable-miss` keeps cache lookup and collapsed-forwarding behavior enabled while the upstream returns `Cache-Control: no-store`, so it measures the repeated miss/no-store path without body collection or storage; after a fill completes without storing, OxiBelt briefly suppresses repeat fill-lock creation for that key while still performing normal lookup and response cacheability checks. `oxibelt-cache-cold-fill` adds a unique query parameter per probe request and returns cacheable public responses, so each measured request exercises fill collection, admission, and in-memory insert instead of reusing a previous hit. Detailed metrics expose cache reasons such as `fill_not_stored`, `fill_lock_timeout`, and `shared_lock_conflict`, plus `oxibelt_cache_fill_stage_duration_ms` stage histograms for lock wait, head decision, body collection, local store, and shared store timing.

OxiRule payload inspection is bounded by `waf.limits.max_body_inspection_bytes`, which defaults to `1048576` bytes. Rules that read `Request.Body`, `Response.Body`, or stream payload text/content helpers inspect only that captured prefix before replaying or forwarding the remaining bytes. Repeated text-oriented helpers such as `Body.Text`, `contains`, `matches`, `containsAny`, `matchesAny`, and `scan` share one decoded text view per request, response, or stream evaluation, and repeated scans of the same pattern set reuse the same result. Contains pattern sets are compiled into a multi-pattern scanner while preserving configured pattern priority, and large text scans run on Tokio's blocking worker pool when OxiBelt is executing on the multi-thread runtime. These optimizations sit above the common HTTP body abstraction, so HTTP/1.1, HTTP/2, and HTTP/3 request bodies all use the same optimized WAF scan path after the bounded prefix has been captured.

The baseline performance fixture also includes `/static/1k.bin`, `/static/16k.bin`, and `/static/1m.bin` static file scenarios. OxiBelt enables `proxy.static_files.sendfile = "auto"` and the opt-in static hot-object cache for that fixture: plaintext HTTP/1.1 static rows are labeled `h1c` and can exercise the guarded Linux sendfile path or hot small-object path, while TLS H1/H2/H3 static rows measure the optimized streaming fallback. nginx is configured with `sendfile on`, and Caddy uses `file_server`, so benchmark profile static rows compare the same static file sizes across all comparators.

In GitHub Actions, `workflow_dispatch` also accepts `performance_iterations`, which defaults to `5`. Reduce it for long manual `benchmark` or `soak` runs when the default repeated sampling would exceed the job budget. The workflow also has a scheduled/manual `Docker aggressive long-run` job that starts after the `Docker performance` matrix succeeds. Scheduled runs use a five-hour steady soak by default. Manual runs must set `aggressive_long_run` and can override `aggressive_long_run_seconds` and `aggressive_long_run_concurrency`. The aggressive long-run uses the `baseline-aggressive-long-run` OxiBelt fixture, which keeps the steady-state baseline tuning but raises the upstream idle pool cap to the scheduled concurrency and enables `connect_error` retry for idempotent requests so transient H1 upstream reconnect churn does not surface as probe `502` noise. That fixture also extends upstream request and first-byte timeouts beyond the default slow POST stress duration, so the slow-client phase remains a resource-stability stressor instead of a 30-second upstream timeout check.

For H2 hot-path investigations, set `OXIBELT_PERF_PROFILE_LABEL=oxibelt-h2` on a local run with host `perf` installed. The harness samples only the load row whose label exactly matches the value, copies the active container's `/usr/local/bin/oxibelt` binary, and writes `perf.data`, `perf report --stdio`, `perf script`, stderr, and metadata under `profiles/` in the artifact directory. Use this as diagnostic evidence only: the profiler changes the measured run and its RPS should not be used as regression-gate or acceptance evidence. Manual `workflow_dispatch` runs can set `performance_h2_profile = true`; the workflow then enables profiling only for the `smoke` `reverse-proxy` shard `1`, target `x86-64-v3`, iteration `1` `oxibelt-h2` row.

To reproduce the scheduled long-run locally with a shorter duration:

```sh
OXIBELT_PERF_SOAK_SECONDS=30 \
OXIBELT_PERF_AGGRESSIVE_STRESS_SECONDS=5 \
tests/scripts/run-proxy-performance.sh --profile soak --serving-type oxibelt-aggressive-long-run --comparators oxibelt
```

## Artifacts

The runner writes:

- `summary.md`: compact Markdown table for human review.
- `results.json`: machine-readable results from the Rust probe.
- `docker-stats.jsonl`: sampled container CPU, memory, network, and block I/O from `docker stats`.
- `resource-snapshots.jsonl`: OxiBelt procfs RSS, FD, task, and thread snapshots for aggressive long-runs.
- `resource-drift.json`: before/after resource drift and gate limits for aggressive long-runs.
- `logs/`: per-container logs.
- `probe-logs/`: stdout and stderr captured from each probe scenario.
- `configs/`: generated effective proxy configs and TLS material used for the run.

The runner generates one-run TLS material and a one-run 64-byte QUIC host key under `configs/*/cert/`. The performance baseline enables `quic.host_key_file` only against that generated key so Retry/stateless reset token behavior is stable within the run without baking shared key material into fixtures or images.

CI runs the `docker-performance` job as 20 parallel `ubuntu-latest` shards for each serving type. Push and pull-request smoke runs intentionally collect all serving-type groups so reverse-proxy, static-file, OxiBelt feature, soak/stress, accept multiplier, and remote signer evidence land in separate artifacts. Each shard uploads one artifact named `oxibelt-docker-performance-<profile>-<serving_type>-shard-<n>` and stores target-specific repeated samples under `x86-64-v2/run-1/` through `x86-64-v3/run-5/` by default. The workflow keeps running later iterations in the same shard after one iteration fails, then fails the job at the end with the failed target/iteration list so artifacts stay complete. In CI, targeted RPS and p99 regression gates run with `OXIBELT_PERF_REGRESSION_GATE_MODE=warn`, so noisy single-iteration threshold misses are recorded while the summary job makes the final primary-target median-based decision. Failed runs also keep the same files when `OXIBELT_TEST_ARTIFACT_DIR` is set.

After the sharded jobs finish, CI runs a `Docker performance summary` job that downloads all `oxibelt-docker-performance-<profile>-*` artifacts from the same workflow run and writes an aggregate artifact named `oxibelt-docker-performance-<profile>-comparison`. That artifact contains:

- `performance-comparison.md`: a run-summary-friendly comparison report.
- `performance-comparison.json`: a stable machine-readable schema for follow-up analysis.
- `performance-delta.md` and `performance-delta.json`: baseline comparison reports when a previous successful run artifact is available.

The comparison job also appends `performance-comparison.md` to the GitHub Actions run summary and fails when `performance-comparison.json` reports blocking median regression gate violations for the primary `x86-64-v3` target. When the previous successful `check-oxibelt.yml` run has a reusable comparison artifact, the summary job passes that baseline report to the aggregate step before gates are evaluated. Threshold misses that baseline evidence explains as stable OxiBelt behavior or comparator movement are recorded under `regression_gates.advisories` and do not fail CI, except for the H2 and H3 nginx-ratio target gates, which remain blocking until the configured target ratio is met. Blocking failures remain under `regression_gates.violations`. If some matrix artifacts are missing because a shard failed before upload or a dependency skipped the performance job, the aggregate report is still generated from the artifacts that exist and records the missing paths in the Warnings section. Missing or malformed `x86-64-v3` rows that make a required regression gate impossible to evaluate are also recorded as blocking regression gate violations, so the summary job fails closed instead of treating incomplete primary-target samples as a pass.

To reproduce the aggregation locally after downloading artifacts:

```sh
cargo run --quiet --locked -p oxibelt --bin oxibelt-performance-aggregate -- \
  --input-dir <downloaded-artifacts-dir> \
  --output-dir <report-dir>
```

## Interpreting Results

CI thresholds are sanity gates, not competitive claims. The job fails when the probe produces no traffic, sees handshake request errors, crosses the configured p99 latency ceiling, or sees load request errors above `OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION`. The default load budget is `100`, which permits at most 100 load transport errors per million completed requests so noisy shared runners do not fail a long smoke soak after millions of successful responses. Set it to `0` to restore strict no-error load gating. `results.json` includes a bounded `error_samples` list for request, handshake, and stress errors, while `probe-logs/` keeps the surrounding probe stdout and stderr. OxiBelt and Caddy HTTP/3 are mandatory gates: if their functional QUIC readiness probe fails, the job fails instead of recording a skipped row. CI sets `OXIBELT_NGINX_H3_MODE=required` for the target-specific nginx comparator images, while local runs default to `auto` and record nginx HTTP/3 as skipped when the selected image lacks `--with-http_v3_module`. The harness also applies a narrower OxiBelt H1/H2 baseline latency-floor gate after the baseline HTTP/1.1, HTTP/2, and HTTP/3 rows are collected; override `OXIBELT_PERF_TCP_BASELINE_MAX_P50_MS` and `OXIBELT_PERF_TCP_BASELINE_MAX_P99_MS` when intentionally running on slower or noisier hosts. Noisy shared runners can move RPS and tail latency substantially, so compare trends across repeated runs and shards and inspect `docker-stats.jsonl` before treating a single result as a regression.

Targeted regression gates pin known-sensitive paths. The aggregate summary checks whether `oxibelt-h2` falls below `OXIBELT_PERF_H2_MIN_NGINX_RATIO` of the matching nginx row, whether `oxibelt-h3` falls below `OXIBELT_PERF_H3_MIN_NGINX_RATIO` of the matching nginx row, whether `oxibelt-static-16k-h1c` falls below `OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO` of Caddy or `OXIBELT_PERF_STATIC_16K_H1C_MIN_NGINX_RATIO` of nginx, and whether `oxibelt-remote-signer-tls-handshake-h2` falls below `OXIBELT_PERF_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO` of `oxibelt-local-key-tls-handshake-h2`. The H2 and H3 nginx-ratio gates default to `0.80` and are blocking target gates: baseline-stable evidence keeps the gap visible in the report but does not downgrade these misses to advisories. The `oxibelt-features` group checks whether WAF enforcing RPS is below `OXIBELT_PERF_WAF_ENFORCING_MIN_RPS`, CRS enforcing RPS is below `OXIBELT_PERF_CRS_ENFORCING_MIN_RPS`, or either WAF/CRS enforcing p99 exceeds its monitor p99 by more than `OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO`. Local runs use `OXIBELT_PERF_REGRESSION_GATE_MODE=fail` by default and fail as soon as one of the per-run targeted gates is crossed. CI sets that mode to `warn` for shard iterations, then the aggregate summary evaluates the threshold variables against median RPS and median p99 ratios across the downloaded samples.

Aggregate gates are baseline-aware when `--baseline-report` points to a previous `performance-comparison.json`. Baseline-aware throughput ratio misses become non-blocking advisories only when the baseline RPS ratio was already below the same threshold, the RPS ratio itself has not worsened by more than `3%`, and the OxiBelt-to-comparator p99 ratio has not worsened by more than `5%`. This keeps known performance gaps visible without failing CI for advisory-eligible gates, while the H2/H3 nginx-ratio target gates, new pass-to-fail threshold crossings, and relative throughput or tail-latency regressions remain blocking. OxiBelt-only absolute RPS misses become advisories when that OxiBelt row is baseline-stable under the same `3%` RPS and `5%` p99 tolerances. WAF/CRS p99 ratio misses become advisories when the enforcing p99 is up by no more than `5%` while the monitor p99 improved by at least `5%`, making the ratio look worse without an enforcing-row regression. If the baseline report is absent, unreadable, missing the needed row, or missing the needed metric, threshold misses remain blocking and the report records why baseline-aware classification was unavailable. The aggregate summary requires the H2, H3, static, remote signer handshake, and WAF/CRS monitor and enforcing rows to be present with usable median metrics; missing median RPS or p99 data is reported with `observed: null`, while non-positive comparator or p99 precondition values are reported with the invalid observed value.

The comparison report is a median-based reference over the repeated shard, target, and iteration samples, not a standalone performance claim. It normalizes labels by comparator prefix within each target CPU, so `oxibelt-h1-keepalive`, `nginx-h1-keepalive`, and `caddy-h1-keepalive` are compared as the same `h1-keepalive` scenario for `x86-64-v2` or `x86-64-v3` separately. Cold handshake rows use `handshake_per_sec`; load rows use `rps`. Comparator ratios use the normalized median throughput for the same target CPU:

```text
oxibelt_vs_nginx = median_rate(oxibelt scenario) / median_rate(nginx same scenario)
oxibelt_vs_caddy = median_rate(oxibelt scenario) / median_rate(caddy same scenario)
```

The report displays both percent and multiplier forms, such as `90.0% of nginx` and `0.90x nginx`. If a comparator row is skipped, missing, or has zero median throughput, the ratio is omitted and the reason is listed under skipped or missing comparator rows.

The accept multiplier comparison report keeps `oxibelt-accept-0_5-*` and `oxibelt-accept-1_0-*` rows out of the nginx/Caddy tables and compares them as OxiBelt-only pairs. A lower accept multiplier can improve steady-state rows by reducing accept-loop and `SO_REUSEPORT` contention, while `accept = 1.0` can recover throughput for handshake-heavy workloads that create new TCP/TLS connections continuously. Treat this as a profile tradeoff: use the default `0.5` baseline for steady-state comparisons, and use the `baseline-accept-1` fixture or `OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO` for handshake-heavy investigations.

nginx and Caddy are measured as common reverse-proxy, cold TLS handshake, and static-file baselines only. OxiBelt-only behavior such as WAF, CRS compatibility, cache policy, TLS resumption diagnostics, remote signer IPC signing overhead, and stress scenarios is measured separately. These OxiBelt-only scenarios are not mixed into nginx/Caddy ratios because they do not measure the same behavior. nginx HTTP/3 is included when the selected image reports `--with-http_v3_module`; otherwise the HTTP/3 comparator row is recorded as skipped in local `auto` mode. If `OXIBELT_NGINX_H3_MODE=required`, missing nginx HTTP/3 module support or a failed functional QUIC probe fails the run. Caddy is configured with its documented `h1 h2 h3` server protocol support and is treated as a mandatory HTTP/3 comparator.

The performance fixtures raise generic connection and per-connection request caps so benchmark and soak profiles measure proxy throughput instead of exercising OxiBelt's or nginx's default limit-enforcement safeguards. Release builds use thin LTO, one codegen unit, and stripped debuginfo; `panic = "abort"` is intentionally not set so postmortem behavior stays conservative.

References:

- Caddy server protocols: https://caddyserver.com/docs/caddyfile/options
- Caddy `reverse_proxy`: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy
- nginx HTTP/3 module: https://nginx.org/en/docs/http/ngx_http_v3_module.html
- nginx QUIC and HTTP/3: https://nginx.org/en/docs/quic.html
