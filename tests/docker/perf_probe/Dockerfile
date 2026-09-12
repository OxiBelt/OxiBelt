FROM rust:1.98.1-trixie@sha256:462a9af3c54fb4718850d3c602fc0e54452c20b1c12a4e4080fdb001d4b9acbf AS builder

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

COPY --from=builder /src/target/release/perf-probe /usr/local/bin/perf-probe

ENTRYPOINT ["/usr/local/bin/perf-probe"]
