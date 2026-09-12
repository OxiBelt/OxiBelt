FROM rust:1.98.1-trixie@sha256:737ba17e6a2ffe14475b59861cd69f3d7152c29c75140bdbf6750befcfda7e6c AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential clang cmake perl pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml /src/Cargo.toml
COPY Cargo.lock /src/Cargo.lock
COPY src /src/src
RUN cargo build --release --locked

FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /tls

COPY --from=builder /src/target/release/protocol-probe /usr/local/bin/protocol-probe

ENTRYPOINT ["/usr/local/bin/protocol-probe"]
