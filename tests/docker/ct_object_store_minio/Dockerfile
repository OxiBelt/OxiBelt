# The MinIO source archive, compiler image, and runtime image are all pinned
# so the CT object-store transport fixture is reproducible and reviewable.
FROM golang:1.24.8-alpine3.22@sha256:3d78beb141d98f42337f1252ecf2a5f20374109929a4c3f6817f9e4179cc0ae5 AS build

ARG MINIO_SOURCE_RELEASE=RELEASE.2025-10-15T17-29-55Z
ARG MINIO_SOURCE_VERSION=2025-10-15T17:29:55Z
ARG MINIO_SOURCE_COMMIT=9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a
ARG MINIO_SOURCE_SHA256=45521908307306e925c98d629e1c17d78c8b72b6ee242b1bfb1409f7d8ee5841

RUN command -v wget >/dev/null \
  && command -v tar >/dev/null \
  && command -v sha256sum >/dev/null \
  && test -s /etc/ssl/certs/ca-certificates.crt \
  && wget --quiet \
    --output-document /tmp/minio.tar.gz \
    "https://codeload.github.com/minio/minio/tar.gz/${MINIO_SOURCE_COMMIT}" \
  && echo "${MINIO_SOURCE_SHA256}  /tmp/minio.tar.gz" | sha256sum -c -s \
  && tar --extract --gzip --file /tmp/minio.tar.gz --directory /tmp \
  && test -d "/tmp/minio-${MINIO_SOURCE_COMMIT}" \
  && mv "/tmp/minio-${MINIO_SOURCE_COMMIT}" /src

WORKDIR /src

RUN test "RELEASE.$(printf '%s' "${MINIO_SOURCE_VERSION}" | sed 's/:/-/g')" = "${MINIO_SOURCE_RELEASE}" \
  && CGO_ENABLED=0 go build -tags kqueue -trimpath -buildvcs=false \
    -ldflags "-s -w \
      -X github.com/minio/minio/cmd.Version=${MINIO_SOURCE_VERSION} \
      -X github.com/minio/minio/cmd.CopyrightYear=2025 \
      -X github.com/minio/minio/cmd.ReleaseTag=${MINIO_SOURCE_RELEASE} \
      -X github.com/minio/minio/cmd.CommitID=${MINIO_SOURCE_COMMIT} \
      -X github.com/minio/minio/cmd.ShortCommitID=9e49d5e7a648" \
    -o /out/minio ./ \
  && /out/minio --version | grep -F "${MINIO_SOURCE_RELEASE}" >/dev/null

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN addgroup --system minio \
  && adduser --system --ingroup minio minio

COPY --from=build /out/minio /usr/local/bin/minio

USER minio

EXPOSE 9000

ENTRYPOINT ["/usr/local/bin/minio"]
