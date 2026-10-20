FROM rust:1.99.1-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential clang cmake perl pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml /src/Cargo.toml
COPY Cargo.lock /src/Cargo.lock
COPY src /src/src
RUN cargo build --release --locked

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /tls

COPY --from=builder /src/target/release/perf-probe /usr/local/bin/perf-probe

ENTRYPOINT ["/usr/local/bin/perf-probe"]
