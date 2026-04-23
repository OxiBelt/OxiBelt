# OxiBelt Proxy

This is the initial implementation of a Rust-based reverse proxy.

Current implementation scope:

- Linux-only build guards
- Architecture guards for `x86_64`, `aarch64`, and `riscv64`
- TLS termination based on `rustls` + the `ring` provider
- Static file-based OCSP stapling
- Downstream HTTP/1.1 and HTTP/2
- Upstream HTTP/1.1 and HTTP/2
- Routing based on hostname + path prefix
- Streaming HTTP body forwarding
- HTTP/2-based gRPC proxy paths
- Compression negotiation passthrough for `zstd`, `gzip`, and `deflate`
- TOML configuration file
- Assumptions aligned with non-root / `readonlyRootFilesystem` operation in Alpine containers

Items intentionally left out of this initial implementation:

- Downstream HTTP/3
- Upstream HTTP/3
- QUIC / WebTransport forwarding
- WebSocket upgrade tunneling
- WebRTC forwarding
- OCSP live fetch / refresh worker

Current constraints:

- `aws-lc-rs` is not used, per request
- As a result, `X25519MLKEM768` cannot be enabled in this implementation under the current upstream `rustls` setup
- If post-quantum key exchange becomes a hard requirement again, the choice of crypto provider should be revisited

In other words, this commit is meant to be a production-oriented foundation. It focuses on locking in module boundaries and the configuration model first, so the HTTP/3/QUIC layer can be added cleanly in the next phase.

## Basic Run

```bash
cargo run -- --config config/oxibelt.toml
```

## Default Port Strategy

- The default internal container port is `8443`
- External `443 -> 8443` forwarding is assumed
- The application does not assume root privileges or Linux capabilities
- It does not require disk writes by default

## Alpine Container Example

See `ops/Dockerfile.alpine`.

## Test Assets

- Rust integration tests live under `tests/rust` and are wired into Cargo from `source/Cargo.toml`
- Docker-based HTTP/HTTPS verification assets live under `tests/docker`
- `tests/scripts/build-targets.sh` verifies both GNU and musl builds for the current Linux architecture
- `tests/scripts/run-proxy-integration.sh` generates fresh TLS material for every run and exercises real HTTP + HTTPS proxying
