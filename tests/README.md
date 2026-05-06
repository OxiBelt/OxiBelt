# OxiBelt Test Assets

- `rust/`: repository-root Cargo integration tests linked from `source/Cargo.toml`
- `docker/`: mock upstream image assets for end-to-end proxy verification
- `scripts/build-targets.sh`: adds the current Linux `gnu` and `musl` targets, then builds both
- `scripts/build-docker-image-artifact.sh`: builds an Alpine musl Docker image for a requested Docker platform (`linux/amd64`, `linux/arm64`, or `linux/riscv64`) and writes it as a loadable image tar artifact
- `riscv64gc-unknown-linux-musl` builds need `clang/libclang`, and either a native `riscv64gc-unknown-linux-musl` toolchain or `riscv64-linux-musl-gcc`
- RISC-V Docker image artifacts use `rust:1.95.0-trixie` as the builder because the official `rust:1.95.0-alpine3.23` image is not published for `riscv64`; the runtime image is still Alpine/musl.
- `scripts/run-proxy-integration.sh`: generates fresh TLS certificates for every run, validates HTTP and HTTPS proxying through Docker, probes `X25519` plus `X25519MLKEM768` TLS negotiation against the current server, and exercises HTTPS upstream proxying with ECH GREASE enabled
- `scripts/run-proxy-integration-matrix.sh`: materializes one Rust-cataloged Docker integration case and validates it in Docker. Cases are grouped by configuration validity, HTTP listener modes, limits, identity/PROXY protocol handling, upstream pools, cache, metrics/health endpoints, routing, proxy headers, upstream TLS, database access logging, WAF request/response behavior, helper behavior, Person proof, protocol startup behavior, and hot reload behavior.
- `scripts/run-browser-webdriver-check.sh`: starts a mock upstream and validates that Chromium or Firefox WebDriver can reach OxiBelt through either a local release binary or an `OXIBELT_DOCKER_IMAGE` container. Pass a scenario name (`basic-navigation`, `waf-request`, `waf-response`, `person-proof`, or `hot-reload`) to run the corresponding browser-level check.
- `rust/oxibelt-docker-integration-matrix.rs`: test-only Rust binary used by CI and scripts to list GitHub matrix entries and materialize Docker/WebDriver case manifests.
- `fixtures/oxibelt-docker-integration-matrix/docker/`: TOML fixture files copied by the matrix materializer for Docker integration cases.
- `docker/mock_upstream/client.py`: test-only HTTPS client used by the integration script. It only connects to the Docker-network proxy endpoint and trusts the generated proxy CA instead of disabling certificate verification.
- `docker/mock_upstream/server.py`: test-only echo upstream. When TLS is enabled, it requires TLS 1.2 or newer.
- `docker/protocol_probe/`: test-only Rust probe that provides HTTP/2 TLS and cleartext h2c upstreams plus HTTP/2 or HTTP/3 downstream clients for protocol proxying matrix cases.
- `docker/postgres/`: test-only PostgreSQL image used by database access-log matrix cases.

The Docker integration flow avoids host bind mounts on purpose. It uses `docker build` and `docker cp`, which behaves more reliably when Docker is exposed through `docker-outside-of-docker`.

Hot reload matrix coverage includes `hot-reload/oxirule-config`, `hot-reload/downstream-tls-only`, and `hot-reload/full-config-tls-listener-rebind`. The browser matrix also runs a `hot-reload` scenario for both Chromium and Firefox, updates config and certificate material in place, sends `SIGHUP`, and asserts browser-visible behavior changed.
