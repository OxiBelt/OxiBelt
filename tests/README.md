# OxiBelt Test Assets

- `rust/`: repository-root Cargo integration tests linked from `source/Cargo.toml`
- `docker/`: mock upstream image assets for end-to-end proxy verification
- `scripts/build-targets.sh`: adds the current Linux `gnu` and `musl` targets, then builds both
- `riscv64gc-unknown-linux-musl` builds need `clang/libclang`, and either a native `riscv64gc-unknown-linux-musl` toolchain or `riscv64-linux-musl-gcc`
- `scripts/run-proxy-integration.sh`: generates fresh TLS certificates for every run, validates HTTP and HTTPS proxying through Docker, probes `X25519` plus `X25519MLKEM768` TLS negotiation against the current server, and exercises HTTPS upstream proxying with ECH GREASE enabled

The Docker integration flow avoids host bind mounts on purpose. It uses `docker build` and `docker cp`, which behaves more reliably when Docker is exposed through `docker-outside-of-docker`.
