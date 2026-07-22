FROM rust:1.97.1-trixie AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential clang cmake perl pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml /src/Cargo.toml
COPY Cargo.lock /src/Cargo.lock
COPY src /src/src
RUN cargo build --release --locked

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/pq-probe /usr/local/bin/pq-probe

ENTRYPOINT ["/usr/local/bin/pq-probe"]
