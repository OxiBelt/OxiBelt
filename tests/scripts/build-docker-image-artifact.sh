#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <docker-platform> <artifact-arch> <output-dir>" >&2
}

platform="${1:-}"
artifact_arch="${2:-}"
output_dir="${3:-}"

if [[ -z "${platform}" || -z "${artifact_arch}" || -z "${output_dir}" ]]; then
  usage
  exit 2
fi

case "${artifact_arch}" in
  amd64|arm64|riscv64) ;;
  *)
    usage
    exit 2
    ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
image_tag="oxibelt:alpine-musl-${artifact_arch}"
image_tar="${output_dir%/}/oxibelt-alpine-musl-${artifact_arch}.tar"
rust_builder_image="rust:1.95.0-alpine3.23"
rust_target=""

if [[ "${artifact_arch}" == "riscv64" ]]; then
  rust_builder_image="rust:1.95.0-trixie"
  rust_target="riscv64gc-unknown-linux-musl"
fi

mkdir -p "${output_dir}"

docker buildx build \
  --platform "${platform}" \
  --file "${repo_root}/source/ops/Dockerfile.alpine" \
  --build-arg "RUST_BUILDER_IMAGE=${rust_builder_image}" \
  --build-arg "OXIBELT_RUST_TARGET=${rust_target}" \
  --tag "${image_tag}" \
  --output "type=docker,dest=${image_tar}" \
  "${repo_root}"

echo "Wrote ${image_tar}"
