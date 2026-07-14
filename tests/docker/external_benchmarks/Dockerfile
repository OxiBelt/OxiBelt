FROM rust:1.97.0-trixie AS oha-builder

ARG OHA_VERSION=1.15.0

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential clang cmake pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN cargo install oha --version "${OHA_VERSION}" --locked

FROM debian:trixie AS wrk-builder

ARG WRK_VERSION=4.2.0
ARG WRK_COMMIT=a211dd5a7050b1f9e8a9870b95513060e72ac4a0
ARG WRK_SHA256=172dd2788b22b210d37a68f11c91e82fdba6583d2a544f04b398a66507031229

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential ca-certificates curl libssl-dev unzip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN curl -fsSL "https://codeload.github.com/wg/wrk/tar.gz/${WRK_COMMIT}" -o wrk.tar.gz && \
    printf '%s  %s\n' "${WRK_SHA256}" wrk.tar.gz | sha256sum -c - && \
    tar -xzf wrk.tar.gz && \
    mv "wrk-${WRK_COMMIT}" "wrk-${WRK_VERSION}" && \
    make -C "wrk-${WRK_VERSION}" -j"$(nproc)"

FROM debian:trixie AS h2load-builder

ARG NGHTTP2_VERSION=1.69.0
ARG NGHTTP2_SHA256=1fb324b6ec2c56f6bde0658f4139ffd8209fa9e77ce98fd7a5f63af8d0e508ad
ARG NGHTTP3_VERSION=1.17.0
ARG NGHTTP3_SHA256=e8b798272b9282045cb83577dcf7bd7fcd22bb3a43aec0eb1a24f675b4cef0b8
ARG NGTCP2_VERSION=1.24.0
ARG NGTCP2_SHA256=7fa5ec2be0f0cbed8bc4ec89c0787dfa9d8ce678f1ed9477c52f30eb1a591207

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
    printf '%s  %s\n' "${NGHTTP3_SHA256}" nghttp3.tar.xz | sha256sum -c - && \
    tar -xf nghttp3.tar.xz && \
    cd "nghttp3-${NGHTTP3_VERSION}" && \
    ./configure --prefix=/opt/nghttp3 --enable-lib-only && \
    make -j"$(nproc)" && \
    make install

RUN curl -fsSL "https://github.com/ngtcp2/ngtcp2/releases/download/v${NGTCP2_VERSION}/ngtcp2-${NGTCP2_VERSION}.tar.xz" -o ngtcp2.tar.xz && \
    printf '%s  %s\n' "${NGTCP2_SHA256}" ngtcp2.tar.xz | sha256sum -c - && \
    tar -xf ngtcp2.tar.xz && \
    cd "ngtcp2-${NGTCP2_VERSION}" && \
    ./configure --prefix=/opt/ngtcp2 --enable-lib-only --with-openssl && \
    make -j"$(nproc)" && \
    make install

RUN curl -fsSL "https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VERSION}/nghttp2-${NGHTTP2_VERSION}.tar.xz" -o nghttp2.tar.xz && \
    printf '%s  %s\n' "${NGHTTP2_SHA256}" nghttp2.tar.xz | sha256sum -c - && \
    tar -xf nghttp2.tar.xz && \
    cd "nghttp2-${NGHTTP2_VERSION}" && \
    PKG_CONFIG_PATH=/opt/nghttp3/lib/pkgconfig:/opt/ngtcp2/lib/pkgconfig \
      LDFLAGS="-Wl,-rpath,/opt/nghttp3/lib -Wl,-rpath,/opt/ngtcp2/lib" \
      ./configure --prefix=/opt/nghttp2 --enable-app --enable-http3 --disable-python-bindings --with-openssl && \
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

RUN h2load --version && \
    h2load --help | grep -q -- '--h3' && \
    ldd "$(command -v h2load)" | grep -q libnghttp3 && \
    ldd "$(command -v h2load)" | grep -q libngtcp2 && \
    oha --version && \
    wrk --version 2>&1 | grep -q '^wrk'

CMD ["sh"]
