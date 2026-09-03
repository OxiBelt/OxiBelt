# The MinIO source archive, compiler image, and runtime image are all pinned
# so the CT object-store transport fixture is reproducible and reviewable.
FROM golang:1.26.4-alpine3.22@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56 AS build

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

FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412

RUN addgroup --system minio \
  && adduser --system --ingroup minio minio

COPY --from=build /out/minio /usr/local/bin/minio

USER minio

EXPOSE 9000

ENTRYPOINT ["/usr/local/bin/minio"]
