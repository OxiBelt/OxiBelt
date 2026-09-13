#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tests/scripts/build-docker-integration-helper-images-artifact.sh <docker-platform> <output-dir>
EOF
}

platform="${1:-}"
output_dir="${2:-}"

if [[ -z "${platform}" || -z "${output_dir}" ]]; then
  usage
  exit 2
fi

if [[ "${platform}" != "linux/amd64" ]]; then
  usage
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
image_tar="${output_dir%/}/oxibelt-docker-integration-helper-images.tar"

mock_upstream_image="oxibelt/mock-upstream:ci"
mock_dns_image="oxibelt/mock-dns:ci"
mock_kubernetes_image="oxibelt/mock-kubernetes:ci"
mock_nomad_image="oxibelt/mock-nomad:ci"
pq_probe_image="oxibelt/pq-probe:ci"
protocol_probe_image="oxibelt/protocol-probe:ci"
postgres_image="oxibelt/postgres:ci"
redis_source_image="valkey/valkey:9.1.2-alpine@sha256:a0dbf4c1d5708782907c10e2c72deff317518518b5288a58416981d9db95d30b"
redis_image="oxibelt/valkey:ci"
coturn_source_image="ghcr.io/coturn/coturn@sha256:aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e"
coturn_image="oxibelt/coturn:ci"

retry_command() {
  local attempts="$1"
  shift
  local delay=5
  local attempt status

  for attempt in $(seq 1 "${attempts}"); do
    "$@" && return 0
    status=$?
    if [[ "${attempt}" == "${attempts}" ]]; then
      return "${status}"
    fi
    printf 'Command failed with status %s; retrying in %ss (%s/%s): %s\n' \
      "${status}" "${delay}" "${attempt}" "${attempts}" "$*" >&2
    sleep "${delay}"
    delay=$((delay * 2))
  done
}

build_helper_image() {
  local image_tag="$1"
  local dockerfile="$2"
  local context="$3"

  retry_command 3 docker buildx build \
    --platform "${platform}" \
    --file "${dockerfile}" \
    --tag "${image_tag}" \
    --load \
    "${context}"
}

mkdir -p "${output_dir}"

for base_image in \
  python:3.14-alpine3.24@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc \
  rust:1.98.1-trixie@sha256:462a9af3c54fb4718850d3c602fc0e54452c20b1c12a4e4080fdb001d4b9acbf \
  debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 \
  postgres:18.6-alpine3.24@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2 \
  "${redis_source_image}" \
  "${coturn_source_image}"; do
  retry_command 3 docker pull --platform "${platform}" "${base_image}"
done

docker tag "${redis_source_image}" "${redis_image}"
docker tag "${coturn_source_image}" "${coturn_image}"

build_helper_image \
  "${mock_upstream_image}" \
  "${repo_root}/tests/docker/mock_upstream/Dockerfile" \
  "${repo_root}/tests/docker/mock_upstream"

build_helper_image \
  "${mock_dns_image}" \
  "${repo_root}/tests/docker/mock_dns/Dockerfile" \
  "${repo_root}/tests/docker/mock_dns"

build_helper_image \
  "${mock_kubernetes_image}" \
  "${repo_root}/tests/docker/mock_kubernetes/Dockerfile" \
  "${repo_root}/tests/docker/mock_kubernetes"

build_helper_image \
  "${mock_nomad_image}" \
  "${repo_root}/tests/docker/mock_nomad/Dockerfile" \
  "${repo_root}/tests/docker/mock_nomad"

build_helper_image \
  "${pq_probe_image}" \
  "${repo_root}/tests/docker/pq_probe/Dockerfile" \
  "${repo_root}/tests/docker/pq_probe"

build_helper_image \
  "${protocol_probe_image}" \
  "${repo_root}/tests/docker/protocol_probe/Dockerfile" \
  "${repo_root}/tests/docker/protocol_probe"

build_helper_image \
  "${postgres_image}" \
  "${repo_root}/tests/docker/postgres/Dockerfile" \
  "${repo_root}/tests/docker/postgres"

retry_command 3 docker save \
  --output "${image_tar}" \
  "${mock_upstream_image}" \
  "${mock_dns_image}" \
  "${mock_kubernetes_image}" \
  "${mock_nomad_image}" \
  "${pq_probe_image}" \
  "${protocol_probe_image}" \
  "${postgres_image}" \
  "${redis_image}" \
  "${coturn_image}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "image_tar=$(basename "${image_tar}")"
    echo "mock_upstream_image=${mock_upstream_image}"
    echo "mock_dns_image=${mock_dns_image}"
    echo "mock_kubernetes_image=${mock_kubernetes_image}"
    echo "mock_nomad_image=${mock_nomad_image}"
    echo "pq_probe_image=${pq_probe_image}"
    echo "protocol_probe_image=${protocol_probe_image}"
    echo "postgres_image=${postgres_image}"
    echo "redis_image=${redis_image}"
    echo "coturn_image=${coturn_image}"
  } >>"${GITHUB_OUTPUT}"
fi

echo "Wrote ${image_tar}"
