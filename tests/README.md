# OxiBelt Test Assets

- `rust/`: repository-root Cargo integration tests linked from `source/Cargo.toml`
- `docker/`: mock upstream image assets for end-to-end proxy verification
- `scripts/build-targets.sh`: adds the current Linux `gnu` and `musl` targets, then builds both
- `scripts/build-docker-image-artifact.sh`: builds an Alpine musl Docker image for a requested Docker platform (`linux/amd64`, `linux/arm64`, or `linux/riscv64`) and writes it as a loadable image tar artifact
- `riscv64gc-unknown-linux-musl` builds need `clang/libclang`, and either a native `riscv64gc-unknown-linux-musl` toolchain or `riscv64-linux-musl-gcc`
- RISC-V Docker image artifacts use `rust:1.95.0-trixie` as the builder because the official `rust:1.95.0-alpine3.23` image is not published for `riscv64`; the runtime image is still Alpine/musl.
- `scripts/run-proxy-integration.sh`: generates fresh TLS certificates for every run, validates HTTP and HTTPS proxying through Docker, probes `X25519` plus `X25519MLKEM768` TLS negotiation against the current server, and exercises HTTPS upstream proxying with ECH GREASE enabled
- `scripts/run-remote-signer-dos.sh`: starts the Docker runtime `oxibelt-keysigner` with a low file-descriptor limit and validates that unauthenticated idle Unix-socket clients are closed by signer-side IPC limits while authenticated `describe_key` requests continue to succeed.
- `scripts/run-proxy-integration-matrix.sh`: materializes one Rust-cataloged Docker integration case and validates it in Docker. Cases are grouped by configuration validity, HTTP listener modes, limits, identity/PROXY protocol handling, upstream pools, cache, metrics/health endpoints, routing, proxy headers, upstream TLS, database access logging, WAF request/response behavior, helper behavior, Person proof, protocol startup behavior, and hot reload behavior.
- `scripts/run-proxy-performance.sh`: runs Docker-network performance smoke, benchmark, or soak profiles after integration coverage. It starts OxiBelt, nginx, Caddy, and `docker/perf_probe/` in one Docker network, fails closed for mandatory OxiBelt/Caddy HTTP/3 probe failures, applies the OxiBelt H1/H2 baseline latency-floor gate, and writes `summary.md`, `results.json`, `docker-stats.jsonl`, container logs, probe logs, and generated configs.
- `scripts/check-proxy-performance-h3-gate.sh`: Docker regression check that runs the performance harness against an HTTP/3-disabled OxiBelt fixture and asserts mandatory OxiBelt HTTP/3 failures are not recorded as skipped.
- `scripts/run-browser-webdriver-check.sh`: starts a mock upstream and validates that Chromium or Firefox WebDriver can reach OxiBelt through either a local release binary or an `OXIBELT_DOCKER_IMAGE` container. Pass a scenario name (`basic-navigation`, `waf-request`, `waf-response`, `person-proof`, or `hot-reload`) to run the corresponding browser-level check.
- `rust/oxibelt-docker-integration-matrix.rs`: test-only Rust binary used by CI and scripts to list GitHub matrix entries and materialize Docker/WebDriver case manifests.
- `rust/ci_workflow_integrity.rs`: Cargo integration test that guards CI job dependencies so structure-check failures cannot skip Rust, Docker image, Docker integration, or browser jobs.
- `fixtures/oxibelt-docker-integration-matrix/docker/`: TOML fixture files copied by the matrix materializer for Docker integration cases.
- `fixtures/oxibelt-docker-performance/`: OxiBelt, nginx, and Caddy configuration fixtures used by the performance runner.
- `docker/mock_upstream/client.py`: test-only HTTPS client used by the integration script. It only connects to the Docker-network proxy endpoint and trusts the generated proxy CA instead of disabling certificate verification.
- `docker/mock_upstream/server.py`: test-only echo upstream. When TLS is enabled, it requires TLS 1.2 or newer.
- `docker/protocol_probe/`: test-only Rust probe that provides HTTP/2 TLS and cleartext h2c upstreams, HTTP/2 or HTTP/3 downstream clients, and WebTransport reload probes for protocol proxying and stale-snapshot drain matrix cases.
- `docker/perf_probe/`: test-only Rust upstream and load generator for HTTP/1.1, HTTP/2, HTTP/3, TLS handshake, and plain-TCP stress measurements.
- `docker/postgres/`: test-only PostgreSQL image used by database access-log matrix cases.

The Docker integration flow avoids host bind mounts on purpose. It uses `docker build` and `docker cp`, which behaves more reliably when Docker is exposed through `docker-outside-of-docker`.

The Docker performance flow follows the same constraint. It copies generated TLS material and configs into containers instead of relying on bind mounts, and removes test containers, networks, and test-only images by label during cleanup.

Hot reload matrix coverage includes `hot-reload/oxirule-config`, `hot-reload/downstream-tls-only`, `hot-reload/full-config-tls-listener-rebind`, and `hot-reload/webtransport-stale-snapshot-drain`. The WebTransport drain case keeps an existing session open through the long-connection grace window while asserting new streams on that drained HTTP/3 bridge are rejected. The browser matrix also runs a `hot-reload` scenario for both Chromium and Firefox, updates config and certificate material in place, sends `SIGHUP`, and asserts browser-visible behavior changed.
