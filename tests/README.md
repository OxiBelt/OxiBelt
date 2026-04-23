# OxiBelt Test Assets

- `rust/`: repository-root Cargo integration tests linked from `source/Cargo.toml`
- `docker/`: mock upstream image assets for end-to-end proxy verification
- `scripts/build-targets.sh`: adds the current Linux `gnu` and `musl` targets, then builds both
- `scripts/run-proxy-integration.sh`: generates fresh TLS certificates for every run and validates HTTP and HTTPS proxying through Docker

The Docker integration flow avoids host bind mounts on purpose. It uses `docker build` and `docker cp`, which behaves more reliably when Docker is exposed through `docker-outside-of-docker`.
