# OxiBelt

OxiBelt is a Rust reverse proxy for Linux edge deployments. It terminates downstream TLS, routes HTTP traffic by host and path, forwards to HTTP/1.1, HTTP/2, or HTTP/3 upstreams, and can apply OxiRule WAF policy on the request and response path.

The current implementation is a production-oriented foundation: configuration is TOML, state is process-local, Docker is the canonical release environment, and the default runtime assumptions fit non-root containers with read-only root filesystems.

## Capabilities

- Downstream HTTP/1.1 and HTTP/2 over TCP, with optional HTTP/3 over QUIC.
- Upstream HTTP/1.1, HTTP/2, and HTTP/3 forwarding.
- TLS termination with `rustls`, `aws-lc-rs`, TLS 1.3 defaults, client certificate authentication, static OCSP stapling, and preferred post-quantum key exchange support.
- Upstream TLS 1.3 ECH in GREASE or configured `ECHConfigList` mode.
- Host and path-prefix routing, prefix replacement, upstream pools, local load-balancing state, and passive or active health marking.
- WebSocket tunneling for HTTP/1.1 upgrade routes and WebTransport forwarding over HTTP/3.
- Forwarded-header normalization, trusted real-IP handling, PROXY protocol intake, rate limits, connection limits, request limits, and bounded response cache support.
- OxiRule request and response WAF rules for rejection, header mutation, tags, response replacement, upstream selection, Person proof challenges, and structured access logs.
- Runtime reload modes for OxiRule-only policy, downstream TLS renewal, or full configuration reload.

See [docs/Specification.md](docs/Specification.md) for the compact behavior spec and current non-goals.

## Quick Start

From the repository root:

```sh
cargo run --manifest-path source/Cargo.toml -- --config source/config/oxibelt.toml
```

Or from `source/`:

```sh
cd source
cargo run -- --config config/oxibelt.toml
```

Validate a configuration without starting listeners:

```sh
cargo run --manifest-path source/Cargo.toml -- \
  --config source/config/oxibelt.toml \
  --check
```

Print the merged, redacted effective configuration:

```sh
cargo run --manifest-path source/Cargo.toml -- \
  --config source/config/oxibelt.toml \
  --dump-effective-config
```

Enable hot reload at startup:

```sh
cargo run --manifest-path source/Cargo.toml -- \
  --config source/config/oxibelt.toml \
  --hot-reload-mode full \
  --hot-reload-poll-interval-ms 1000
```

Send `SIGHUP` to trigger an immediate reload check when hot reload is enabled.

## Documentation

- [Technical specification](docs/Specification.md): proxy behavior, request pipeline, runtime model, security posture, and non-goals.
- [Configuration reference](docs/Configuration.md): TOML sections, includes, path rules, validation, and examples.
- [OxiRule WAF reference](docs/OxiRule.md): rule shape, expression language, actions, object model, helpers, and examples.
- [OxiRule examples](docs/example/OxiRule.md): cookbook-style request, response, routing, Person proof, and access-log rules.

The default example configuration is [source/config/oxibelt.toml](source/config/oxibelt.toml).

## Project Layout

```text
source/                         Rust reverse proxy crate
source/src/proxy/http.rs         HTTP reverse proxy behavior
source/src/tls.rs                TLS configuration and client/server setup
source/src/config.rs             Configuration loading and validation
source/src/routes.rs             Route matching logic
source/config/oxibelt.toml       Example/default configuration
source/ops/Dockerfile.alpine     Release Docker image
tests/rust/                      Rust integration tests
tests/docker/                    Docker test services and probes
tests/scripts/                   Build and integration orchestration
docs/                            Specification and references
```

Root-level documentation uses root-relative paths. If a command must run from `source/`, the command block says so explicitly.

## Docker Image

Build the release image from the repository root:

```sh
docker build --pull -t oxibelt -f source/ops/Dockerfile.alpine .
```

The Alpine image runs as UID/GID `10001:10001`, exposes `8443/tcp`, and expects its default entry configuration at:

```text
/etc/oxibelt/config/oxibelt.toml
```

The standard container layout is:

```text
/etc/oxibelt/config   OxiBelt TOML configuration and included modules
/etc/oxibelt/cert     TLS certificates, private keys, CA roots, OCSP, ECH files
/etc/oxibelt/oxirule  External .oxirule.toml rule files
```

Example hardened local run:

```sh
docker run --rm -p 8443:8443 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --mount type=bind,src=/mnt/user0/oxibelt/config,dst=/etc/oxibelt/config,readonly \
  --mount type=bind,src=/mnt/user0/oxibelt/cert,dst=/etc/oxibelt/cert,readonly \
  --mount type=bind,src=/mnt/user0/oxibelt/oxirule,dst=/etc/oxibelt/oxirule,readonly \
  oxibelt
```

Mounted files must be readable by UID `10001`. For private keys, prefer ownership or group permissions over broad world-readable permissions.

For certificate renewal workflows, mount stable certificate/key paths under `/etc/oxibelt/cert` and enable `runtime.hot_reload.mode = "downstream_tls"` or `full`. OxiBelt tracks symlink target changes so renewed certificate files can be imported without restarting the process.

## Local Checks

Recommended Rust checks from the repository root:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Docker and integration checks:

```sh
tests/scripts/build-targets.sh
tests/scripts/run-proxy-integration.sh
```

`tests/scripts/run-proxy-integration.sh` generates fresh TLS material for each run and cleans up test resources. The Docker matrix also covers reload behavior and browser-visible behavior where applicable.

## Current Non-Goals

The current implementation intentionally leaves ACME HTTP-01 handling, live OCSP fetch/refresh, request-wide structured access logging outside OxiRule, sticky-cookie upstream sessions, WebRTC media forwarding, streaming-safe WAF text scanning, and passing `103 Early Hints` as future work. See [docs/Specification.md](docs/Specification.md#non-goals-and-reserved-work) for the full list.
