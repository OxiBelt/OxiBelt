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
- RISC-V Docker image artifacts use `rust:1.96.0-trixie` as the builder because the official `rust:1.96.0-alpine3.23` image is not published for `riscv64`; the runtime image is still Alpine/musl.
- `scripts/run-proxy-integration.sh`: generates fresh TLS certificates for every run, validates HTTP and HTTPS proxying through Docker, probes `X25519` plus `X25519MLKEM768` TLS negotiation against the current server, and exercises HTTPS upstream proxying with ECH GREASE enabled
- `scripts/run-remote-signer-dos.sh`: starts the Docker runtime `oxibelt-keysigner` with token-file auth, signer UID `10002`, proxy/probe UID `10001`, a shared signer socket group, and a low file-descriptor limit; it validates that unauthenticated idle Unix-socket clients are closed by signer-side IPC limits while authenticated `describe_key` requests continue to succeed.
- `scripts/run-proxy-integration-matrix.sh`: materializes one Rust-cataloged Docker integration case and validates it in Docker. Cases are grouped by configuration validity, HTTP listener modes, limits, identity/PROXY protocol handling, upstream pools, cache, metrics/health endpoints, routing, proxy headers, upstream TLS, remote signer downstream TLS, SNI forwarding, access-log export, database mitigation queues, WAF request/response behavior, helper behavior, Person proof, protocol startup behavior, and hot reload behavior.
- `scripts/run-proxy-performance.sh`: runs Docker-network performance smoke, benchmark, or soak profiles after integration coverage. It starts OxiBelt, nginx, Caddy, OpenResty, and `docker/perf_probe/` in one Docker network, fails closed for mandatory OxiBelt/Caddy/OpenResty HTTP/3 probe failures, applies the OxiBelt H1/H2 baseline latency-floor gate, includes `accept-multipliers` and `remote-signer` OxiBelt-only comparisons, optionally runs h2load/oha/wrk external validation without adding those rows to `results.json`, can run profile-only diagnostic replay rows without adding them to `results.json`, and writes `summary.md`, `results.json`, `external-results.json`, `profile-results.json`, external tool outputs, profiling outputs, `docker-stats.jsonl`, container logs, probe logs, and generated configs.
- `scripts/check-proxy-performance-h3-gate.sh`: Docker regression check that runs the performance harness against an HTTP/3-disabled OxiBelt fixture and asserts mandatory OxiBelt HTTP/3 failures are not recorded as skipped.
- `scripts/check-performance-aggregate-incomplete-gate.sh`: Docker regression check that creates a focused OxiBelt-only static performance smoke artifact, aggregates it, and asserts the missing Caddy static regression gate fails closed instead of passing with incomplete samples.
- `scripts/run-browser-webdriver-check.sh`: starts a mock upstream and validates that Chromium or Firefox WebDriver can reach OxiBelt through either a local release binary or an `OXIBELT_DOCKER_IMAGE` container. Pass a scenario name (`basic-navigation`, `waf-request`, `waf-response`, `person-proof`, or `hot-reload`) to run the corresponding browser-level check.
- `rust/oxibelt-docker-integration-matrix.rs`: test-only Rust binary used by CI and scripts to list GitHub matrix entries and materialize Docker/WebDriver case manifests.
- `rust/ci_workflow_integrity.rs`: Cargo integration test that guards CI job dependencies so structure-check failures cannot skip Rust, Docker image, Docker integration, or browser jobs.
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

CI builds AMD64 Alpine musl images for `x86-64-v2`, `x86-64-v3`, and `x86-64-v4`. Docker integration, remote signer, and browser WebDriver jobs auto-select the newest supported artifact on each runner. Docker performance and aggressive long-run jobs intentionally use the `x86-64-v3` artifact so benchmark summaries compare the same binary target; unsupported performance runners upload `unsupported-cpu.json` and are excluded from aggregate calculations, while unsupported aggressive long-run runners fail and should be manually rerun.
After the OxiBelt image artifacts are built in non-release CI, Trivy scans the `amd64v2`, `amd64`, `amd64v4`, `arm64`, and `riscv64` image artifacts. The scan job reports vulnerabilities as a Markdown table in `GITHUB_STEP_SUMMARY`, uploads the raw JSON report, and keeps findings report-only; a separate canonical-repository job submits Trivy's GitHub-format SBOM output to the Dependency Snapshot API on push, schedule, same-repository PR, or manual runs with `submit_dependency_snapshots` enabled.
The release workflow rebuilds the same artifact matrix from a validated strict
tag and verifies the CI-only Cargo version rewrite and Docker labels. Each
reusable per-architecture row builds an unprivileged image tar, records
BuildKit-resolved inputs, scans the local tar as report-only pre-publish
evidence, and produces a validated CycloneDX SBOM. An isolated package-write
job publishes the canonical platform digest without checking out or executing
release build code. A separate OIDC-enabled job publishes its CycloneDX SBOM,
SLSA provenance v1, and keyless Cosign signature. A read-only job verifies the
exact digest, issuer, repository, release workflow, tag ref, source commit,
GitHub-hosted builder, signature, provenance, and SBOM from OCI before stable
platform aliases can be promoted.

The top-level release workflow waits for all five reusable rows, publishes the
canonical multi-architecture index from the verified `amd64` (x86-64-v3),
`arm64`, and `riscv64` digests, re-verifies those platform attestations, and
composes an architecture-preserving aggregate SBOM bound to the resulting
index digest. It then signs, attests, and independently verifies the index. A
read-only rootless Docker-backed Minikube gate must admit that exact signed
digest and reject a historical unsigned OxiBelt digest before mutable index
aliases can be promoted. QEMU is used only for the RISC-V image; AMD64
and ARM64 build natively on their release runners. Build tags matching
`major.minor.patch-build.<8 hex chars>` may publish from tag push events;
stable and `major.minor.patch-beta.N` tags publish from GitHub release or
manual dispatch events. Workflow integrity tests in
`rust/ci_workflow_integrity.rs` enforce this fail-closed topology,
platform/tag/signature/provenance/SBOM coverage, immutable action pins,
admission dependencies, and permission separation. Static Helm and policy
checks are provided by `check-helm-image-digest.sh` and
`check-image-admission-policy.sh`; `run-image-admission-policy.sh` is the live
admission proof.
Consumer verification commands and the trust boundary are documented in
[`docs/SupplyChain.md`](../docs/SupplyChain.md).

Hot reload matrix coverage includes `hot-reload/oxirule-config`, `hot-reload/downstream-tls-only`, `hot-reload/full-config-tls-listener-rebind`, `hot-reload/telemetry-tracing-disable`, and `hot-reload/webtransport-stale-snapshot-drain`. The WebTransport drain case keeps an existing session open through the long-connection grace window while asserting new streams on that drained HTTP/3 bridge are rejected. The telemetry case verifies full reload rebuilds tracing state and stops `traceparent` propagation when tracing is disabled. The browser matrix also runs a `hot-reload` scenario for both Chromium and Firefox, updates config and certificate material in place, sends `SIGHUP`, and asserts browser-visible behavior changed.
