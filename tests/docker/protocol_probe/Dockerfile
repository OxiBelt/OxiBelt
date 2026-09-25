FROM rust:1.98.1-trixie@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546 AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential clang cmake perl pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src/tests/docker/protocol_probe
COPY tests/docker/protocol_probe/Cargo.toml ./Cargo.toml
COPY tests/docker/protocol_probe/Cargo.lock ./Cargo.lock
COPY tests/docker/protocol_probe/src ./src
COPY source/third_party/h3 /src/source/third_party/h3
COPY source/third_party/quinn /src/source/third_party/quinn
COPY source/third_party/quinn-proto /src/source/third_party/quinn-proto
COPY source/third_party/web-transport-proto /src/source/third_party/web-transport-proto
COPY source/third_party/web-transport-quinn /src/source/third_party/web-transport-quinn
RUN cargo build --release --locked

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /tls /fixture

COPY --from=builder /src/tests/docker/protocol_probe/target/release/protocol-probe /usr/local/bin/protocol-probe

ENTRYPOINT ["/usr/local/bin/protocol-probe"]
