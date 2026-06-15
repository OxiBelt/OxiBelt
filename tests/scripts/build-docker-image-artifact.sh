#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <docker-platform> <artifact-arch> <output-dir>" >&2
  echo "artifact-arch: amd64v2, amd64, amd64v4, arm64, or riscv64" >&2
}

default_oxibelt_source="https://github.com/OxiBelt/OxiBelt"

sanitize_source_url() {
  local source_url="$1"
  source_url="${source_url%%#*}"
  source_url="${source_url%%\?*}"
  sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]+@#\1#' <<<"${source_url}"
}

detect_oxibelt_source() {
  if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" ]]; then
    sanitize_source_url "${GITHUB_SERVER_URL%/}/${GITHUB_REPOSITORY}"
    return
  fi

  local remote_url
  remote_url="$(git -C "${repo_root}" config --get remote.origin.url 2>/dev/null || true)"
  if [[ -n "${remote_url}" ]]; then
    sanitize_source_url "${remote_url}"
    return
  fi

  echo "${default_oxibelt_source}"
}

platform="${1:-}"
artifact_arch="${2:-}"
output_dir="${3:-}"

if [[ -z "${platform}" || -z "${artifact_arch}" || -z "${output_dir}" ]]; then
  usage
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
image_tag="oxibelt:alpine-musl-${artifact_arch}"
image_tar="${output_dir%/}/oxibelt-alpine-musl-${artifact_arch}.tar"
rust_builder_image="rust:1.96.0-alpine3.24"
rust_target=""
rust_target_cpu=""
oxibelt_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "${repo_root}/source/Cargo.toml" | head -n 1)"
oxibelt_revision="$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || true)"
oxibelt_created="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
oxibelt_source="$(detect_oxibelt_source)"

case "${artifact_arch}" in
  amd64v2)
    if [[ "${platform}" != "linux/amd64" ]]; then
      usage
      exit 2
    fi
    rust_target="x86_64-unknown-linux-musl"
    rust_target_cpu="x86-64-v2"
    ;;
  amd64)
    if [[ "${platform}" != "linux/amd64" ]]; then
      usage
      exit 2
    fi
    rust_target="x86_64-unknown-linux-musl"
    rust_target_cpu="x86-64-v3"
    ;;
  amd64v4)
    if [[ "${platform}" != "linux/amd64" ]]; then
      usage
      exit 2
    fi
    rust_target="x86_64-unknown-linux-musl"
    rust_target_cpu="x86-64-v4"
    ;;
  arm64|riscv64) ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ -z "${oxibelt_version}" ]]; then
  oxibelt_version="dev"
fi

if [[ -z "${oxibelt_revision}" ]]; then
  oxibelt_revision="unknown"
fi

if [[ -z "${oxibelt_source}" ]]; then
  oxibelt_source="${default_oxibelt_source}"
fi

if [[ "${artifact_arch}" == "riscv64" ]]; then
  rust_builder_image="rust:1.96.0-trixie"
  rust_target="riscv64gc-unknown-linux-musl"
fi

mkdir -p "${output_dir}"

docker buildx build \
  --platform "${platform}" \
  --file "${repo_root}/source/ops/Dockerfile.alpine" \
  --build-arg "RUST_BUILDER_IMAGE=${rust_builder_image}" \
  --build-arg "OXIBELT_RUST_TARGET=${rust_target}" \
  --build-arg "OXIBELT_RUST_TARGET_CPU=${rust_target_cpu}" \
  --build-arg "OXIBELT_VERSION=${oxibelt_version}" \
  --build-arg "OXIBELT_REVISION=${oxibelt_revision}" \
  --build-arg "OXIBELT_CREATED=${oxibelt_created}" \
  --build-arg "OXIBELT_SOURCE=${oxibelt_source}" \
  --tag "${image_tag}" \
  --output "type=docker,dest=${image_tar}" \
  "${repo_root}"

echo "Wrote ${image_tar}"
