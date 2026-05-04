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
oxibelt_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "${repo_root}/source/Cargo.toml" | head -n 1)"
oxibelt_revision="$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || true)"
oxibelt_created="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
oxibelt_source="$(git -C "${repo_root}" config --get remote.origin.url 2>/dev/null || true)"

if [[ -z "${oxibelt_version}" ]]; then
  oxibelt_version="dev"
fi

if [[ -z "${oxibelt_revision}" ]]; then
  oxibelt_revision="unknown"
fi

if [[ -z "${oxibelt_source}" ]]; then
  oxibelt_source="https://github.com/OxiBelt/OxiBelt"
fi

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
  --build-arg "OXIBELT_VERSION=${oxibelt_version}" \
  --build-arg "OXIBELT_REVISION=${oxibelt_revision}" \
  --build-arg "OXIBELT_CREATED=${oxibelt_created}" \
  --build-arg "OXIBELT_SOURCE=${oxibelt_source}" \
  --tag "${image_tag}" \
  --output "type=docker,dest=${image_tar}" \
  "${repo_root}"

echo "Wrote ${image_tar}"
