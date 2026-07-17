# OxiBelt Test Assets

- `rust/`: repository-root Cargo integration tests linked from `source/Cargo.toml`
- `docker/`: mock upstream image assets for end-to-end proxy verification
- `scripts/build-targets.sh`: adds the current Linux `gnu` and `musl` targets, then builds both
- `scripts/check-tests-rustfmt.sh`: enforces `tests/rustfmt.toml` formatting for tracked Rust files under `tests/`, including Docker probe crates
- `scripts/build-docker-image-artifact.sh`: builds an Alpine musl Docker image for a requested Docker platform (`linux/amd64`, `linux/arm64`, or `linux/riscv64`) and writes it as a loadable image tar artifact. AMD64 builds accept `amd64v2`, `amd64`, and `amd64v4`; the default `amd64` artifact name remains `oxibelt-alpine-musl-amd64-image` and targets `x86-64-v3`. Release CI can override OCI metadata with `OXIBELT_DOCKER_IMAGE_VERSION`, `OXIBELT_DOCKER_IMAGE_REVISION`, `OXIBELT_DOCKER_IMAGE_CREATED`, `OXIBELT_DOCKER_IMAGE_SOURCE`, and `OXIBELT_DOCKER_IMAGE_REF_NAME`.
- `scripts/build-docker-integration-helper-images-artifact.sh`: builds the Docker integration helper images once for CI and writes a loadable tar artifact containing the mock upstream, DNS, Kubernetes, PQ probe, protocol probe, PostgreSQL, and Valkey images.
- `scripts/build-external-benchmark-image-artifact.sh`: builds the reusable h2load/oha/wrk external benchmark image as `oxibelt/external-benchmarks:ci` and writes `oxibelt-external-benchmark-image.tar` for CI.
- `scripts/select-amd64-docker-image-artifact.sh`: selects the best loadable AMD64 Docker artifact for the current Linux runner from `/proc/cpuinfo`, or validates a required target such as `x86-64-v3` for benchmark jobs.
- `riscv64gc-unknown-linux-musl` builds need `clang/libclang`, and either a native `riscv64gc-unknown-linux-musl` toolchain or `riscv64-linux-musl-gcc`
- RISC-V Docker image artifacts use `rust:1.97.0-trixie` as the builder because the official `rust:1.97.0-alpine3.24` image is not published for `riscv64`; the runtime image is still Alpine/musl.
- `scripts/run-proxy-integration.sh`: generates fresh TLS certificates for every run, validates HTTP and HTTPS proxying through Docker, probes `X25519` plus `X25519MLKEM768` TLS negotiation against the current server, and exercises HTTPS upstream proxying with ECH GREASE enabled
- `scripts/run-remote-signer-dos.sh`: starts the Docker runtime `oxibelt-keysigner` with token-file auth, signer UID `10002`, proxy/probe UID `10001`, a shared signer socket group, and a low file-descriptor limit; it validates that unauthenticated idle Unix-socket clients are closed by signer-side IPC limits while authenticated `describe_key` requests continue to succeed.
- `scripts/run-proxy-integration-matrix.sh`: materializes one Rust-cataloged Docker integration case and validates it in Docker. Cases are grouped by configuration validity, HTTP listener modes, limits, identity/PROXY protocol handling, upstream pools, cache, metrics/health endpoints, routing, proxy headers, upstream TLS, remote signer downstream TLS, SNI forwarding, access-log export, database mitigation queues, WAF request/response behavior, helper behavior, Person proof, protocol startup behavior, and hot reload behavior.
- `scripts/run-proxy-performance.sh`: runs Docker-network performance smoke, benchmark, or soak profiles after integration coverage. It starts OxiBelt, nginx, Caddy, OpenResty, and `docker/perf_probe/` in one Docker network, fails closed for mandatory OxiBelt/Caddy/OpenResty HTTP/3 probe failures, applies the OxiBelt H1/H2 baseline latency-floor gate, includes `accept-multipliers` and `remote-signer` OxiBelt-only comparisons, optionally runs h2load/oha/wrk external validation without adding those rows to `results.json`, can run profile-only diagnostic replay rows without adding them to `results.json`, and writes `summary.md`, `results.json`, `external-results.json`, `profile-results.json`, external tool outputs, profiling outputs, `docker-stats.jsonl`, container logs, probe logs, and generated configs.
- `scripts/check-proxy-performance-h3-gate.sh`: Docker regression check that runs the performance harness against an HTTP/3-disabled OxiBelt fixture and asserts mandatory OxiBelt HTTP/3 failures are not recorded as skipped.
- `scripts/check-performance-aggregate-incomplete-gate.sh`: Docker regression check that creates a focused OxiBelt-only static performance smoke artifact, aggregates it, and asserts the missing Caddy static regression gate fails closed instead of passing with incomplete samples.
- `scripts/run-browser-webdriver-check.sh`: starts a mock upstream and validates that Chromium or Firefox WebDriver can reach OxiBelt through either a local release binary or an `OXIBELT_DOCKER_IMAGE` container. Pass a scenario name (`basic-navigation`, `waf-request`, `waf-response`, `person-proof`, or `hot-reload`) to run the corresponding browser-level check.
- `rust/oxibelt-docker-integration-matrix.rs`: test-only Rust binary used by CI and scripts to list GitHub matrix entries and materialize Docker/WebDriver case manifests.
- `rust/ci_workflow_integrity.rs`: Cargo integration test that guards CI job dependencies so structure-check failures cannot skip Rust, Docker image, Docker integration, or browser jobs, ensures every dependency-free `check-oxibelt` entry job skips runs initiated by Dependabot, and enforces privilege separation for the Dependabot pull-request retirement workflow.
- `fixtures/oxibelt-docker-integration-matrix/docker/`: per-case shell checks and extra fixture files copied by the matrix materializer for Docker integration cases.
- `fixtures/oxibelt-docker-performance/`: OxiBelt, nginx, Caddy, and OpenResty configuration fixtures used by the performance runner.
- `docker/mock_upstream/client.py`: test-only HTTPS client used by the integration script. It connects through Docker-network endpoints and trusts generated test CAs instead of disabling certificate verification; SNI forwarding cases can set a distinct TLS server name.
- `docker/mock_upstream/server.py`: test-only echo upstream. When TLS is enabled, it requires TLS 1.2 or newer.
- `docker/protocol_probe/`: test-only Rust probe that provides HTTP/2 TLS and cleartext h2c upstreams, HTTP/2 or HTTP/3 downstream clients, and WebTransport reload probes for protocol proxying and stale-snapshot drain matrix cases.
- `docker/perf_probe/`: test-only Rust upstream and load generator for HTTP/1.1, HTTP/2, HTTP/3, TLS handshake, and plain-TCP stress measurements.
- `docker/postgres/`: test-only PostgreSQL image used by database access-log and mitigation matrix cases.

The Docker integration flow avoids host bind mounts on purpose. It uses `docker build` and `docker cp`, which behaves more reliably when Docker is exposed through `docker-outside-of-docker`.

CI prebuilds Docker integration helper images once as the `oxibelt-docker-integration-helper-images` artifact and loads that tar in each Docker integration matrix job. Local `run-proxy-integration-matrix.sh` runs still build helper images on demand unless `OXIBELT_MOCK_UPSTREAM_IMAGE`, `OXIBELT_MOCK_DNS_IMAGE`, `OXIBELT_MOCK_KUBERNETES_IMAGE`, `OXIBELT_MOCK_NOMAD_IMAGE`, `OXIBELT_PQ_PROBE_IMAGE`, `OXIBELT_PROTOCOL_PROBE_IMAGE`, `OXIBELT_POSTGRES_IMAGE`, or `OXIBELT_REDIS_IMAGE` is set. Set `OXIBELT_REQUIRE_PRELOADED_HELPER_IMAGES=1` only after loading those images so missing helpers fail before Docker tries to pull from a registry.

The Docker performance flow follows the same constraint. It copies generated TLS material and configs into containers instead of relying on bind mounts, and removes test containers, networks, and test-only images by label during cleanup. `docker/perf_probe/` remains the primary OxiBelt-specific benchmark client and the only source for primary regression-gate rows. The optional external benchmark layer reuses the same fixtures and records diagnostic outputs under `external-h2load/*.txt`, `external-oha/*.json`, `external-wrk/*.txt`, and `external-results.json`; failures warn by default unless `OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE=fail`. Diagnostic profiling replay rows record CPU `perf` and memory drift evidence under `profiles/cpu/`, `profiles/memory/`, and `profile-results.json`; they also warn by default and only fail when `OXIBELT_PERF_DIAGNOSTIC_GATE_MODE=fail`. CI keeps that raw diagnostic evidence in `oxibelt-docker-performance-<profile>-<serving_type>-shard-<n>` artifacts, while the summary job downloads only slim `oxibelt-docker-performance-summary-input-<profile>-<serving_type>-shard-<n>` artifacts containing `results.json`, `external-results.json`, `profile-results.json`, `iteration-status.json`, and `unsupported-cpu.json`.

CI builds AMD64 Alpine musl images for `x86-64-v2`, `x86-64-v3`, and `x86-64-v4`. Docker integration, remote signer, and browser WebDriver jobs auto-select the newest supported artifact on each runner. Docker performance runs each supported `x86-64-v2` and `x86-64-v3` artifact sequentially in the same matrix job so summaries can compare both ISA targets, while aggressive long-run jobs intentionally use `x86-64-v3`; unsupported performance targets upload `unsupported-cpu.json` and are excluded from aggregate calculations, while unsupported aggressive long-run runners fail and should be manually rerun.
After the OxiBelt image artifacts are built in non-release CI, Trivy scans the `amd64v2`, `amd64`, `amd64v4`, `arm64`, and `riscv64` image artifacts. The scan job reports vulnerabilities as a Markdown table in `GITHUB_STEP_SUMMARY`, uploads the raw JSON report, and keeps findings report-only; a separate canonical-repository job submits Trivy's GitHub-format SBOM output to the Dependency Snapshot API on push, schedule, same-repository PR, or manual runs with `submit_dependency_snapshots` enabled.
Kubernetes integration keeps the supported Kubernetes `v1.31.14` and Helm 3 compatibility lane. A separate read-only compatibility job runs the full static chart checks with Helm `v4.2.3`, starts a digest-pinned Kubernetes `v1.36.1` Kind node with Kind `v0.32.0`, and submits the default rendered chart to the API server with `--dry-run=server` using kubectl `v1.36.2`.
The release workflow rebuilds the same artifact matrix from a validated strict
tag and verifies the CI-only Cargo version rewrite, Docker labels, role, and
executable inventory. Each reusable per-architecture row builds an unprivileged
image tar, records the Buildx digest metadata used by canonical publication,
scans the local tar as report-only pre-publish evidence, and produces a
validated CycloneDX platform SBOM. An isolated package-write job publishes each
canonical platform digest without checking out or executing release build code.
Separate OIDC jobs create GitHub API-hosted SLSA provenance and CycloneDX SBOM
attestations, verify exact workflow/source/subject/predicate/timestamp policy,
and gate platform promotion. The attestation jobs do not push Cosign signatures,
SBOMs, or bundles to GHCR.

The top-level release workflow waits for all 25 role/architecture rows and publishes
the canonical multi-architecture index from the `amd64` (x86-64-v3), `arm64`,
and `riscv64` digests for each role. It cross-checks those child digests against
their platform SBOMs, composes a CycloneDX 1.7 index SBOM that points to the
separate platform inventories, and gates index alias promotion on GitHub
attestation verification. QEMU is used only for the RISC-V image;
AMD64 and ARM64 build natively on their release runners. Build tags matching
`major.minor.patch-build.<8 hex chars>` may publish from tag push events;
stable and `major.minor.patch-beta.N` tags publish from GitHub release or
manual dispatch events. Workflow integrity tests in
`rust/ci_workflow_integrity.rs` enforce the role/platform/tag topology,
immutable action pins, executable inventories, and permission separation. The
static Helm digest check remains in `check-helm-image-digest.sh`.
The exact API verification/download model, consumer trust boundary, historical
OCI referrer warning, and operator-owned admission guidance are documented in
[`docs/SupplyChain.md`](../docs/SupplyChain.md).

Hot reload matrix coverage includes `hot-reload/oxirule-config`, `hot-reload/downstream-tls-only`, `hot-reload/full-config-tls-listener-rebind`, `hot-reload/telemetry-tracing-disable`, and `hot-reload/webtransport-stale-snapshot-drain`. The WebTransport drain case keeps an existing session open through the long-connection grace window while asserting new streams on that drained HTTP/3 bridge are rejected. The telemetry case verifies full reload rebuilds tracing state and stops `traceparent` propagation when tracing is disabled. The browser matrix also runs a `hot-reload` scenario for both Chromium and Firefox, updates config and certificate material in place, sends `SIGHUP`, and asserts browser-visible behavior changed.

## Concurrency and Fault-Injection Invariants

Race-sensitive tests use model exploration, explicit barriers, observed metrics, or bounded polling. Sleeps and timeouts are safety ceilings, not the condition that decides whether an invariant passed. Every injected runtime fault must prove recovery with a later successful operation and must leave bounded task, queue, pool, or fill gauges at zero.

The CI cadences below apply to non-Dependabot workflow events. Dependabot-triggered `check-oxibelt` runs intentionally skip every dependency-free entry job, so their downstream jobs do not allocate runners. After GitHub completes an authenticated Dependabot `Check OxiBelt` run, the separate `Close Dependabot pull requests` workflow validates the source commit with a read-only token, then gives a second job only `issues: write` and `pull-requests: write`. That job never checks out or executes pull-request code, creates or reopens one `dependencies` issue for each canonical Dependabot pull request associated with the completed run, and closes the source pull request only after the issue is readable. Existing open Dependabot pull requests can be reconciled together from the default branch with `workflow_dispatch` and the exact `close-all-open-dependabot-prs` confirmation; repeated runs reuse the per-pull-request marker instead of creating duplicate issues.

| Test type | Deterministic trigger | Preserved invariant and recovery assertion | CI cadence |
| --- | --- | --- | --- |
| Lifecycle Loom model | Bounded interleavings of admin drain, overload drain, and shutdown bit transitions | Drain sources cannot clear each other, shutdown is monotonic with one first caller, and no snapshot reports ready while any drain source remains active | Dedicated AMD64 Loom step on push, pull request, daily schedule, and manual dispatch |
| Shared-state Loom model | Bounded failure, success, and status-snapshot interleavings | Healthy state has no degraded epoch, degraded state has one coherent nonzero epoch, and one success transition clears it without a stale timestamp | Dedicated AMD64 Loom step on every workflow event |
| Redis latency | `shared-state/redis-delay-isolation` uses `CLIENT PAUSE` | Requests fail closed within configured bounds while health and metrics remain responsive; resuming Redis drains gauges and a fresh request succeeds | `state-data` Docker matrix on every workflow event |
| PostgreSQL latency | `shared-state/postgres-delay-isolation` holds a targeted `PGAPPNAME` lock session and releases it with `pg_cancel_backend` | Backend work stays bounded and observable; cancellation releases the lock, cleanup drains, and a fresh request succeeds | `state-data` Docker matrix on every workflow event |
| Redis disconnect and reconnect | `shared-state/redis-disconnect-reconnect` stops and restarts the exact labeled Redis container | Ambiguous sockets are discarded, reconnect work is bounded by the pool circuit, and restart produces a new healthy connection with zero active/waiter gauges | `state-data` Docker matrix on every workflow event |
| Partial configuration rollout | Controller observations model committed A, partially converged B, rejection or timeout, rollback to A, and a distinct C | Partial B never commits, rollback restores the last committed revision/digest, unchanged failed B stays blocked, and a later distinct candidate may proceed; local invalid reload input never publishes a torn generation | Rust tests on AMD64 and ARM64; existing Kind rollout wiring on every workflow event |
| Lock poisoning | Unit tests poison task-registry, cache-fill, response-cache, and critical connection-limit locks | Recoverable locks emit one bounded recovery event and accept later work; critical capacity corruption stays failed closed and unready | Rust tests on AMD64 and ARM64 |
| Background task termination | Paused Tokio time plus explicit task-factory barriers inject return, error, panic, and shutdown during backoff | Critical failure removes readiness until a stable replacement, optional failure remains ready but degraded, fatal failure does not restart, and normal shutdown creates no replacement | Rust tests on AMD64 and ARM64 |
| Backend cancellation | Abort after a fake Redis server observes a command but before it returns a reply | The ambiguous connection is never reused or replayed, permits and gauges drain, and the next command opens a fresh connection and succeeds | Rust tests on AMD64 and ARM64 |
| Retry storm | `upstream-pools/retry-storm-budget` releases a synchronized burst into a one-active, zero-queued retry budget | Original and retry metrics reconcile with upstream attempts, retry concurrency never exceeds one, budget rejection prevents amplification, gauges drain, and the same route succeeds after fault removal | `proxy` Docker matrix on every workflow event |
| Cache-fill stampede | `cache/collapsed-forwarding-metrics` gates one leader while synchronized followers join the fill | One origin response fills the cache, all followers receive the same generation, waiter metrics reconcile, no lock timeout/error occurs, and a later cache hit succeeds | `cache` Docker matrix on every workflow event |
| Active H2/H3 shutdown | `lifecycle/process-signal-h2-h3-drain` gates active H2 and H3 requests before pre-drain and `SIGTERM` | Readiness fails while liveness remains healthy, in-flight requests finish before the single graceful deadline, the process exits successfully, and a restarted process serves fresh H2/H3 requests | `config-runtime` Docker matrix on every workflow event |

The Docker fault cases use only rootless `docker`, unique run labels, isolated networks, exact container names, bounded control inputs, and label-scoped cleanup. They do not use privileged containers, host networking, `netem`, `iptables`, broad prune operations, or `docker-rootful`. Failed matrix jobs retain the existing case materialization, proxy/upstream/probe logs, and container diagnostics through `OXIBELT_TEST_ARTIFACT_DIR`.

Run the focused cases locally with:

```sh
tests/scripts/run-proxy-integration-matrix.sh shared-state redis-delay-isolation
tests/scripts/run-proxy-integration-matrix.sh shared-state postgres-delay-isolation
tests/scripts/run-proxy-integration-matrix.sh shared-state redis-disconnect-reconnect
tests/scripts/run-proxy-integration-matrix.sh upstream-pools retry-storm-budget
tests/scripts/run-proxy-integration-matrix.sh cache collapsed-forwarding-metrics
tests/scripts/run-proxy-integration-matrix.sh lifecycle process-signal-h2-h3-drain
```
