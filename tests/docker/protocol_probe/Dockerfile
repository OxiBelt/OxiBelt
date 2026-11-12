FROM rust:1.99.1-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS builder

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

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /tls /fixture

COPY --from=builder /src/tests/docker/protocol_probe/target/release/protocol-probe /usr/local/bin/protocol-probe

ENTRYPOINT ["/usr/local/bin/protocol-probe"]
