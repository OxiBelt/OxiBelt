#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tests/scripts/build-external-benchmark-image-artifact.sh <docker-platform> <output-dir>
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
image_tag="oxibelt/external-benchmarks:ci"
image_tar="${output_dir%/}/oxibelt-external-benchmark-image.tar"

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

mkdir -p "${output_dir}"

for base_image in rust:1.99.1-trixie@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc debian:trixie@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308 debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad; do
  retry_command 3 docker pull --platform "${platform}" "${base_image}"
done

retry_command 3 docker buildx build \
  --platform "${platform}" \
  --file "${repo_root}/tests/docker/external_benchmarks/Dockerfile" \
  --tag "${image_tag}" \
  --output "type=docker,dest=${image_tar}" \
  "${repo_root}/tests/docker/external_benchmarks"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "image_tag=${image_tag}"
    echo "image_tar=$(basename "${image_tar}")"
  } >>"${GITHUB_OUTPUT}"
fi

echo "Wrote ${image_tar}"
