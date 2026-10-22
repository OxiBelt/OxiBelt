FROM rust:1.99.1-trixie@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS builder

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
