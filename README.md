# OxiBelt

OxiBelt is a Rust reverse proxy for Linux edge deployments. It terminates downstream TLS, routes HTTP traffic by host and path, forwards to HTTP/1.1, HTTP/2, or HTTP/3 upstreams, and can apply OxiRule WAF policy on the request and response path.

The current implementation is a production-oriented foundation: configuration is TOML, state is process-local by default with optional shared-state backends, Docker is the canonical release environment, and the default runtime assumptions fit non-root containers with read-only root filesystems while using available CPU parallelism for runtime and listener workers.

## Capabilities

- Downstream HTTP/1.1 and HTTP/2 over TCP, with optional HTTP/3 over QUIC.
- Upstream HTTP/1.1, HTTP/2, and HTTP/3 forwarding.
- TLS termination with `rustls`, `aws-lc-rs`, TLS 1.3 defaults, client certificate authentication, static/live OCSP stapling, opt-in upstream OCSP/CRLite revocation checks, experimental CRLite enforcement with local or managed filters, and preferred post-quantum key exchange support.
- Upstream TLS 1.3 ECH in GREASE or configured `ECHConfigList` mode.
- Host and path-prefix routing, prefix replacement, upstream pools, local load-balancing state, and passive or active health marking.
- WebSocket tunneling, opt-in generic HTTP/1.1 Upgrade and CONNECT tunneling, gRPC-Web translation, and WebTransport forwarding over HTTP/3.
- Forwarded-header normalization, trusted real-IP handling, PROXY protocol intake, TCP upstream/stream-target PROXY protocol egress, rate limits, connection limits, request limits, and bounded response cache support.
- A compiled-in, versioned `edge-secure-medium` v1 operational profile for a
  strict public-edge baseline, with an inspectable expanded configuration.
- Opt-in TCP/UDP stream listeners for raw L4 forwarding to fixed targets or stream pools, with visible TLS/QUIC SNI-aware passthrough routing.
- OxiRule request, response, and stream WAF rules for rejection, header mutation, tags, response replacement, upstream selection, Person proof challenges, structured access logs, bounded HTTP body scanning, WebSocket/WebTransport payload inspection, and optional CRS-compatible anomaly scoring.
- Request-wide structured system access logs with OCSF or ECS JSON stdout and OTLP Logs delivery.
- Prometheus metrics with aggregate or detailed route/upstream/protocol labels, plus optional W3C tracecontext propagation and OTLP trace export.
- Runtime reload modes for OxiRule-only policy, downstream TLS renewal, or full configuration reload, with graceful listener drain for in-flight requests and long-lived tunnels.
- Optional Kubernetes Gateway API controller that translates `HTTPRoute` and
  passthrough `TLSRoute` resources into a controller-owned immutable OxiBelt
  TOML include and rolls the selected workload independently of the runtime.

See [docs/Specification.md](docs/Specification.md) for the compact behavior spec and current non-goals.

## Quick Start

From the repository root:

```sh
cargo run -p oxibelt --bin oxibelt -- --config source/config/oxibelt.toml
```

Or from `source/`:

```sh
cd source
cargo run --bin oxibelt -- --config config/oxibelt.toml
```

Validate a configuration without starting listeners:

```sh
cargo run -p oxibelt --bin oxibelt -- \
  --config source/config/oxibelt.toml \
  --check
```

Print the merged, redacted effective configuration:

```sh
cargo run -p oxibelt --bin oxibelt -- \
  --config source/config/oxibelt.toml \
  --dump-effective-config
```

Run the production preflight doctor without starting listeners:

```sh
cargo run -p oxibeltctl -- \
  doctor --config source/config/oxibelt.toml
```

Doctor can also inspect rendered Kubernetes resources without applying them:

```sh
cargo run -p oxibeltctl -- \
  doctor --helm-rendered deploy/rendered --format sarif --fail-on warning
```

Use `--helm-chart CHART` with repeatable `--helm-values FILE` for a bounded,
client-side Helm render, or `--kubernetes` for read-only live inspection. See
`docs/Configuration.md` for source-combination and Kubernetes credential-safety
rules.

Enable hot reload at startup:

```sh
cargo run -p oxibelt --bin oxibelt -- \
  --config source/config/oxibelt.toml \
  --hot-reload-mode full \
  --hot-reload-poll-interval-ms 1000
```

Send `SIGHUP` to trigger an immediate reload check when hot reload is enabled.

Full reloads activate replacement listeners before old listener generations drain. OxiBelt also handles Ctrl-C and `SIGTERM` by marking the instance draining, keeping `/live` healthy, returning `503` from `/ready`, optionally waiting `runtime.drain.shutdown_delay_ms`, and then draining listeners up to `runtime.drain.graceful_timeout_ms`. On Unix, `SIGUSR1` starts that irreversible drain without exiting so a trusted local supervisor can withdraw readiness before final termination. Long-lived WebSocket, generic Upgrade, CONNECT, WebTransport, and TCP stream bridges get `runtime.drain.long_connection_close_delay_ms` before forced close.

The admin listener exposes lifecycle control when enabled:

```text
GET  /admin/v1/config/status
GET  /admin/v1/config/effective
POST /admin/v1/config/validate
POST /admin/v1/config/diff
POST /admin/v1/config/load
POST /admin/v1/config/rollback
POST /admin/v1/files/sync
GET  /admin/v1/tls/downstream
POST /admin/v1/tls/downstream/reload
GET  /admin/v1/lifecycle
POST /admin/v1/lifecycle/drain
POST /admin/v1/lifecycle/undrain
```

The `oxibeltctl` operations CLI wraps the Admin API without bypassing IPM
authorization:

```sh
cargo run -p oxibeltctl -- status
cargo run -p oxibeltctl -- support-bundle --redact
cargo run -p oxibeltctl -- auth check --action config:GetStatus --resource '*'
```

For break-glass recovery, `oxibeltctl --break-glass-access ...` reads the
operator token from `OXIBELT_BREAK_GLASS_TOKEN`, while OxiBelt stores only an
Argon2id PHC hash in `[[ipm.credentials]].break_glass_access_token_hash`.
Break-glass access credentials are accepted on the Admin listener only and are
ignored for downstream route IPM requests.

### `edge-secure-medium` v1

Select the built-in secure-medium profile at the top level of the main
configuration or an included module:

```toml
profile = "edge-secure-medium"
# Optional in source: omission is permanently pinned to version 1.
profile_version = 1

[waf]
enabled = true
```

The profile is compiled into the binary; it is not a remote catalog and does
not download profile content. It supplies the strict v1 baseline, but public
server names, TLS certificate/key or remote-signer material, trusted proxy
CIDRs, IPM/audit settings, and a stable QUIC host key when HTTP/3 is enabled
remain deliberate operator inputs. The expanded, redacted effective output
always materializes `profile_version = 1`:

```sh
cargo run -p oxibelt --bin oxibelt -- \
  --config source/config/oxibelt.toml \
  --dump-effective-config
```

For Kubernetes, start from
[deploy/helm/oxibelt/examples/edge-secure-medium-v1-values.yaml](deploy/helm/oxibelt/examples/edge-secure-medium-v1-values.yaml).
It selects v1, takes public SNI names, and projects one named Secret entry for
the stable QUIC host key without embedding any secret material. That projected
Secret value must be the base64 text for 64 random bytes, as described in the
configuration reference. The normal chart defaults remain unprofiled. The
secure Helm companion requires Kubernetes 1.31+ and selects three replicas,
hostname/zone distribution, a one-Pod disruption budget, and the fixed
300-second `SIGUSR1` pre-stop drain inside a 360-second grace. It enables the
opt-in NetworkPolicy baseline, but operators must still declare every
route-specific egress dependency and validate it with their enforcing CNI.
ServiceAccount token mounting is chart-level hardening: data-plane Pods have no
Kubernetes API token by default, while explicitly configured API discovery
receives a bounded projected credential and scoped RBAC. The runtime profile
itself does not provide certificate-to-IPM identity, general idempotency,
stronger audit, or release-provenance work; see the configuration reference for
the complete contract and boundaries.

## Documentation

- [Technical specification](docs/Specification.md): proxy behavior, request pipeline, runtime model, security posture, and non-goals.
- [Configuration reference](docs/Configuration.md): TOML sections, includes, path rules, validation, and examples.
- [Operational-profile contract](docs/Configuration.md#operational-profiles):
  `edge-secure-medium` v1 syntax, protected defaults, required inputs, Helm
  companion values, and compatibility rules.
- [Gateway API controller](docs/GatewayAPI.md): Kubernetes GatewayClass,
  Gateway, HTTPRoute, TLSRoute, ReferenceGrant, and Service translation.
- [OxiRule WAF reference](docs/OxiRule.md): rule shape, expression language, actions, object model, helpers, and examples.
- [OxiRule examples](docs/example/OxiRule.md): cookbook-style request, response, routing, Person proof, and access-log rules.
- [Doc/source drift audit](docs/DocSourceDriftAudit.md): current HEAD documentation, spec, source, and guard-gap audit findings.
- [Product threat model](docs/ThreatModel.md): assets, trust boundaries, attacker-controlled inputs, security claims, and severity context.
- [Security policy](SECURITY.md): supported releases, private vulnerability reporting, disclosure, and official image scope.
- [Contributing guide](CONTRIBUTING.md): contributor workflow, security requirements, PR checklist, and commit-message format.

The default example configuration is [source/config/oxibelt.toml](source/config/oxibelt.toml).

## Project Layout

```text
Cargo.toml                      Rust workspace and shared dependency policy
source/                         Integrated data-plane and Admin runtime crate
source/apps/                    Controller, CLI, keysigner, and netport binaries
source/crates/                  Shared external-control protocol and HTTP crates
source/assets/                  Build-validated embedded runtime assets
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

Build the standalone compatibility image from the repository root:

```sh
docker build --pull -t oxibelt -f source/ops/Dockerfile.alpine .
```

The same Dockerfile exposes `dataplane`, `controller`, `tools`, and `keysigner`
targets. For example:

```sh
docker build --pull --target dataplane -t oxibelt-dataplane -f source/ops/Dockerfile.alpine .
docker build --pull --target controller -t oxibelt-gateway-controller -f source/ops/Dockerfile.alpine .
```

The build regenerates `ui/person-proof`, validates the Person Proof and Admin
OpenAPI inputs, and embeds both into the `oxibelt` binary. Node.js, pnpm, Cargo,
and the Rust compiler are build-stage inputs only.

Official releases publish these role-specific repositories from the same
version and source revision:

| Repository | Docker target | Executable inventory | Purpose |
| --- | --- | --- | --- |
| `ghcr.io/oxibelt/oxibelt` | `standalone` | `oxibelt`, `oxibeltctl`, `oxibelt-keysigner`, `oxibelt-netport-switcher` | Backward-compatible single-container distribution. |
| `ghcr.io/oxibelt/oxibelt-dataplane` | `dataplane` | `oxibelt` | Hardened public runtime with co-located Admin and Person Proof, but no operator or Kubernetes binaries. |
| `ghcr.io/oxibelt/oxibelt-gateway-controller` | `controller` | `oxibelt-gateway-controller` | External Kubernetes orchestration. |
| `ghcr.io/oxibelt/oxibelt-tools` | `tools` | `oxibeltctl` | Offline and Admin operator workflows. |
| `ghcr.io/oxibelt/oxibelt-keysigner` | `keysigner` | `oxibelt-keysigner` | Optional isolated private-key operations. |

CI scans every role/architecture artifact separately. Release CI publishes a
per-role platform manifest and multi-architecture index, then attaches a
role-specific keyless signature, SLSA provenance statement, and OCI-linked
CycloneDX SBOM before promoting aliases. See [Release Supply-Chain
Verification](docs/SupplyChain.md) for verification commands and trust
boundaries.

Published tags use strict OxiBelt release tags such
as `15.2.0`, `15.2.0-beta.1`, or `15.2.0-build.4f43abcd`; `v`-prefixed tags
are rejected. Stable releases also update major Alpine musl aliases such as
`5-alpine-musl-amd64`, plus the multi-arch `latest` and `alpine-musl` aliases after all required arch-specific tags have been published.

```sh
docker pull ghcr.io/oxibelt/oxibelt:15.2.0-alpine-musl
docker pull ghcr.io/oxibelt/oxibelt:15.2.0-alpine-musl-amd64
docker pull ghcr.io/oxibelt/oxibelt:5-alpine-musl-amd64
```

The Alpine image runs as UID/GID `10001:10001`, exposes `8443/tcp` and `8443/udp`, and expects its default entry configuration at:

```text
/etc/oxibelt/config/oxibelt.toml
```

The standard container layout is:

```text
/etc/oxibelt/config   OxiBelt TOML configuration and included modules
/etc/oxibelt/cert     TLS certificates, private keys, CA roots, OCSP, ECH files
/etc/oxibelt/oxirule  External .oxirule.toml rule files
```

The standalone image also bundles `/usr/local/bin/oxibeltctl` for Admin API
operations, `/usr/local/bin/oxibelt-netport-switcher` for opt-in privileged
data-plane port brokerage, and `/usr/local/bin/oxibelt-keysigner` for backward
compatibility while keeping the entrypoint on `oxibelt`. The Gateway Controller
is intentionally available only in its role-specific image. For example:

```sh
docker exec -it oxibelt oxibeltctl status
docker exec -it oxibelt oxibeltctl lifecycle drain
docker run --rm --entrypoint /usr/local/bin/oxibelt-gateway-controller \
  --mount type=bind,src=/path/to/manifests,dst=/manifests,readonly \
  ghcr.io/oxibelt/oxibelt-gateway-controller:15.2.0-alpine-musl \
  render --input /manifests --output -
```

Run a mounted configuration through local preflight by overriding the entrypoint:

```sh
docker run --rm --entrypoint /usr/local/bin/oxibeltctl \
  --mount type=bind,src=/mnt/user0/oxibelt/config,dst=/etc/oxibelt/config,readonly \
  --mount type=bind,src=/mnt/user0/oxibelt/cert,dst=/etc/oxibelt/cert,readonly \
  --mount type=bind,src=/mnt/user0/oxibelt/oxirule,dst=/etc/oxibelt/oxirule,readonly \
  oxibelt doctor --config /etc/oxibelt/config/oxibelt.toml
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

To bind container port `443` while keeping the normal OxiBelt process
unprivileged, set `[runtime.netport_switcher] enabled = true` and start the
bundled wrapper as root with only the bind and setuid/setgid capabilities it
needs:

```sh
docker run --rm \
  --user 0:0 \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --cap-add=SETUID \
  --cap-add=SETGID \
  --security-opt no-new-privileges \
  -p 443:443/tcp \
  -p 443:443/udp \
  --entrypoint /usr/local/bin/oxibelt-netport-switcher \
  oxibelt --config /etc/oxibelt/config/oxibelt.toml
```

Mounted files must be readable by UID `10001`. For private keys, prefer ownership or group permissions over broad world-readable permissions. For stronger isolation, enable `[tls.remote_signer]` and run `oxibelt-keysigner` as signer UID `10002` while OxiBelt runs as UID `10001`. OxiBelt should read certificate chains and `keysigner-token.b64`, and connect to the signer Unix socket through a supplemental signer socket group; it should not receive private key files.

The default release configuration uses `worker_threads = "auto"`, `runtime.accept.workers = "auto"`, and `quic.socket.workers = "auto"`. Auto sizing uses Rust `std::thread::available_parallelism()` with configurable multipliers, so container CPU limits are reflected without adding cgroup-specific code. Multi-worker TCP and HTTP/3 listeners require explicit `reuse_port = true`. If HTTP/3 Retry/stateless reset tokens should remain stable across restarts, mount a deployment-local 64-byte base64 `quic.host_key_file` under `/etc/oxibelt/cert`; the image does not include shared key material.

When remote signing is used with `--read-only`, the signer socket directory must be a writable tmpfs or volume because Unix socket bind creates a filesystem entry. For example:

```sh
--tmpfs /run/oxibelt-keysigner:rw,noexec,nosuid,nodev,mode=0770
```

In a sidecar deployment, mount the same socket directory into both the OxiBelt container and the signer container, make it writable by signer UID/GID `10002:10002`, and run OxiBelt with supplemental group `10002` so it can connect to the default `0660` socket. Mount private keys and `keysigner-token.b64` read-only into the signer container; give OxiBelt a readable copy of `keysigner-token.b64` and certificate chains, not private key files. Start the signer with `--token-file /etc/oxibelt/cert/keysigner-token.b64 --allow-peer-uid 10001`; `--socket-mode` accepts only `0600` or `0660`. Rotate the token with an atomic replace, for example `openssl rand -base64 32 > keysigner-token.b64.tmp && mv keysigner-token.b64.tmp keysigner-token.b64`; rotation-capable deployments should mount the containing directory or a projected secret volume so the updated path is visible inside both containers. Single-file read-only binds are appropriate only for fixed-token test fixtures. Keep signer IPC bounded with the default `oxibelt-keysigner` connection cap and I/O deadline, and use peer UID/GID allowlists where possible.

For certificate renewal workflows, mount stable certificate/key paths under `/etc/oxibelt/cert` and enable `runtime.hot_reload.mode = "downstream_tls"` or `full`. OxiBelt tracks symlink target changes so renewed certificate files can be imported without restarting the process.

## Local Checks

Recommended Rust checks from the repository root:

```sh
cargo fmt --check
cargo audit
cargo deny check advisories
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Docker and integration checks:

```sh
tests/scripts/build-targets.sh
tests/scripts/run-proxy-integration.sh
tests/scripts/run-proxy-performance.sh --profile smoke --comparators oxibelt,nginx,caddy,openresty
```

`tests/scripts/run-proxy-integration.sh` generates fresh TLS material for each run and cleans up test resources. The Docker matrix also covers reload behavior and browser-visible behavior where applicable.
`tests/scripts/run-proxy-performance.sh` runs Docker-network performance smoke, benchmark, or soak profiles and writes `summary.md`, `results.json`, per-container logs, generated configs, and sampled Docker stats. See [docs/Performance.md](docs/Performance.md) for profile details and result interpretation.

Release builds use thin LTO, one codegen unit, and stripped debuginfo. `panic = "abort"` is intentionally not enabled.

## Current Non-Goals

OxiBelt intentionally keeps ACME challenge handling, including HTTP-01 and DNS-01, out of scope and expects external certificate automation to provision TLS material. Use an ACME client such as Certbot or Lego, including the `certbot/certbot` or `goacme/lego` Docker images when containerized renewal fits your deployment, then point OxiBelt at the generated certificate and key files.

This keeps ACME account keys, DNS provider API tokens, challenge credentials, and optionally TLS private keys outside the OxiBelt process and container trust boundary. If a proxy vulnerability ever allowed remote code execution, memory disclosure, or a logic error that exposed OxiBelt process state, the compromised process should not also contain the credentials needed to issue arbitrary new TLS certificates or export configured private keys, especially through DNS-01 provider tokens.

Downstream ECH configuration and CRS stream-payload inspection for
WebSocket/WebTransport remain reserved or deferred. SNI-based TCP TLS
forwarding, same-port QUIC forwarding, dedicated TCP/UDP stream proxying, live
OCSP fetch/refresh, opt-in upstream OCSP/CRLite revocation checks, and
sticky-cookie upstream pools are current features. See
[docs/FeatureStatus.md](docs/FeatureStatus.md) for the canonical lifecycle
matrix and [docs/Specification.md](docs/Specification.md#non-goals-and-reserved-work)
for the design rationale behind reserved work.

## Disclaimer
This project is developed with some LLM Agents or LLM assistances like ChatGPT Codex. This can introduce security issues, unintended behavior, or inaccuracies. However, all code changes are reviewed or approved by people to mitigate potential risks and many GitHub Action workflows are in place to enforce code quality and security checks.
