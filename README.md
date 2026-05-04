# OxiBelt Proxy

This is the initial implementation of a Rust-based reverse proxy.

Current implementation scope:

- Linux-only build guards
- Architecture guards for `x86_64`, `aarch64`, and `riscv64`
- TLS termination based on `rustls` + the `aws-lc-rs` provider
- Static file-based OCSP stapling
- Upstream TLS 1.3 ECH support for GREASE and configured ECHConfigList modes
- Downstream HTTP/1.1 and HTTP/2
- Upstream HTTP/1.1 and HTTP/2
- Routing based on hostname + path prefix
- Streaming HTTP body forwarding
- HTTP/2-based gRPC proxy paths
- Compression negotiation passthrough for `zstd`, `gzip`, and `deflate`
- Initial OxiRule WAF support for request/response rules, header mutation, tags, request rejection, upstream-error response policy, and response replacement
- TOML configuration file
- Assumptions aligned with non-root / `readonlyRootFilesystem` operation in Alpine containers

Items intentionally left out of this initial implementation:

- Downstream HTTP/3
- Upstream HTTP/3
- QUIC / WebTransport forwarding
- WebSocket upgrade tunneling
- WebRTC forwarding
- OCSP live fetch / refresh worker
- Streaming-safe WAF body content inspection
- Upstream pool load balancing actions

Current constraints:

- `aws-lc-rs` is used as the crypto provider
- `X25519MLKEM768` is enabled and preferred in the default rustls key exchange group order
- ECH is currently supported where OxiBelt acts as an upstream TLS client; downstream ECH termination depends on server-side ECH support in the TLS provider
- The project now targets Rust 1.95

In other words, this commit is meant to be a production-oriented foundation. It focuses on locking in module boundaries and the configuration model first, so the HTTP/3/QUIC layer can be added cleanly in the next phase.

## Basic Run

From the repository root:

```bash
cargo run --manifest-path source/Cargo.toml -- --config source/config/oxibelt.toml
```
Or from `source/`
```bash
cd source
cargo run -- --config config/oxibelt.toml
```

## Documentation

- [OxiBelt configuration](docs/Configuration.md)
- [OxiRule WAF specification](docs/OxiRule.md)

## Default Port Strategy

- The default internal container port is `8443`
- External `443 -> 8443` forwarding is assumed
- The application does not assume root privileges or Linux capabilities
- It does not require disk writes by default

## Alpine Container Example

From the repository root:

```bash
docker build -t oxibelt -f source/ops/Dockerfile.alpine .
```

## Test Assets

- Rust integration tests live under `tests/rust` and are wired into Cargo from `source/Cargo.toml`
- Docker-based HTTP/HTTPS verification assets live under `tests/docker`
- `tests/scripts/build-targets.sh` verifies both GNU and musl builds for the current Linux architecture
- `riscv64gc-unknown-linux-musl` uses `aws-lc-rs` bindgen during dependency builds, so `clang/libclang` must be available when targeting it
- `tests/scripts/run-proxy-integration.sh` generates fresh TLS material for every run, exercises real HTTP + HTTPS proxying, proves that both `X25519` and `X25519MLKEM768` negotiate with the current `aws-lc-rs`-based server, and verifies HTTPS upstream proxying with ECH GREASE enabled
