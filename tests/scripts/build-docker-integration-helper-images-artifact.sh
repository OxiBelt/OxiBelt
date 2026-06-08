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
redis_image="valkey/valkey:8-alpine"

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
  python:3.14-alpine3.23 \
  python:3.12-alpine \
  rust:1.95.0-trixie \
  debian:trixie-slim \
  postgres:18-alpine \
  "${redis_image}"; do
  retry_command 3 docker pull --platform "${platform}" "${base_image}"
done

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
  "${redis_image}"

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
  } >>"${GITHUB_OUTPUT}"
fi

echo "Wrote ${image_tar}"
