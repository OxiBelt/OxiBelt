FROM rust:1.95.0-trixie AS oha-builder

ARG OHA_VERSION=1.12.1

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential clang cmake pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN cargo install oha --version "${OHA_VERSION}" --locked

FROM debian:trixie AS wrk-builder

ARG WRK_VERSION=4.2.0

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential ca-certificates curl libssl-dev unzip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN curl -fsSL "https://github.com/wg/wrk/archive/${WRK_VERSION}.tar.gz" -o wrk.tar.gz && \
    tar -xzf wrk.tar.gz && \
    make -C "wrk-${WRK_VERSION}" -j"$(nproc)"

FROM debian:trixie AS h2load-builder

ARG NGHTTP2_VERSION=1.69.0
ARG NGHTTP3_VERSION=1.15.0
ARG NGTCP2_VERSION=1.22.1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      autoconf \
      automake \
      build-essential \
      ca-certificates \
      curl \
      libc-ares-dev \
      libev-dev \
      libssl-dev \
      libtool \
      make \
      pkg-config \
      zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN curl -fsSL "https://github.com/ngtcp2/nghttp3/releases/download/v${NGHTTP3_VERSION}/nghttp3-${NGHTTP3_VERSION}.tar.xz" -o nghttp3.tar.xz && \
    tar -xf nghttp3.tar.xz && \
    cd "nghttp3-${NGHTTP3_VERSION}" && \
    ./configure --prefix=/opt/nghttp3 --enable-lib-only && \
    make -j"$(nproc)" && \
    make install

RUN curl -fsSL "https://github.com/ngtcp2/ngtcp2/releases/download/v${NGTCP2_VERSION}/ngtcp2-${NGTCP2_VERSION}.tar.xz" -o ngtcp2.tar.xz && \
    tar -xf ngtcp2.tar.xz && \
    cd "ngtcp2-${NGTCP2_VERSION}" && \
    PKG_CONFIG_PATH=/opt/nghttp3/lib/pkgconfig \
      ./configure --prefix=/opt/ngtcp2 --enable-lib-only --with-openssl --with-nghttp3=/opt/nghttp3 && \
    make -j"$(nproc)" && \
    make install

RUN curl -fsSL "https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VERSION}/nghttp2-${NGHTTP2_VERSION}.tar.xz" -o nghttp2.tar.xz && \
    tar -xf nghttp2.tar.xz && \
    cd "nghttp2-${NGHTTP2_VERSION}" && \
    PKG_CONFIG_PATH=/opt/nghttp3/lib/pkgconfig:/opt/ngtcp2/lib/pkgconfig \
      LDFLAGS="-Wl,-rpath,/opt/nghttp3/lib -Wl,-rpath,/opt/ngtcp2/lib" \
      ./configure --prefix=/opt/nghttp2 --enable-app --disable-python-bindings --with-openssl --with-libngtcp2 --with-libnghttp3 && \
    make -j"$(nproc)" && \
    make install

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libev4 libssl3 zlib1g && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /tls

COPY --from=h2load-builder /opt/nghttp2 /opt/nghttp2
COPY --from=h2load-builder /opt/nghttp3 /opt/nghttp3
COPY --from=h2load-builder /opt/ngtcp2 /opt/ngtcp2
COPY --from=oha-builder /usr/local/cargo/bin/oha /usr/local/bin/oha
COPY --from=wrk-builder /build/wrk-4.2.0/wrk /usr/local/bin/wrk

ENV PATH="/opt/nghttp2/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/nghttp2/lib:/opt/nghttp3/lib:/opt/ngtcp2/lib"

RUN h2load --h3 --version && \
    oha --version && \
    wrk --version 2>&1 | grep -q '^wrk'

CMD ["sh"]
