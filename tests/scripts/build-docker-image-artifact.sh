#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <docker-platform> <artifact-arch> <output-dir> [role]" >&2
  echo "artifact-arch: amd64v2, amd64, amd64v4, arm64, or riscv64" >&2
  echo "role: standalone (default), dataplane, dataplane-strict, controller, tools, or keysigner" >&2
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
role="${4:-standalone}"

if [[ -z "${platform}" || -z "${artifact_arch}" || -z "${output_dir}" || "$#" -gt 4 ]]; then
  usage
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
artifact_prefix=""
case "${role}" in
  standalone)
    artifact_prefix="oxibelt"
    ;;
  dataplane)
    artifact_prefix="oxibelt-dataplane"
    ;;
  dataplane-strict)
    artifact_prefix="oxibelt-dataplane-strict"
    ;;
  controller)
    artifact_prefix="oxibelt-gateway-controller"
    ;;
  tools)
    artifact_prefix="oxibelt-tools"
    ;;
  keysigner)
    artifact_prefix="oxibelt-keysigner"
    ;;
  *)
    usage
    exit 2
    ;;
esac
image_tag="${artifact_prefix}:alpine-musl-${artifact_arch}"
image_tar="${output_dir%/}/${artifact_prefix}-alpine-musl-${artifact_arch}.tar"
build_metadata="${output_dir%/}/${artifact_prefix}-alpine-musl-${artifact_arch}-build-metadata.json"
artifact_contract="${output_dir%/}/${artifact_prefix}-alpine-musl-${artifact_arch}-artifact-contract.json"
build_metadata_tmp=""
rust_toolchain_version="1.97.1"
rust_builder_image="rust:${rust_toolchain_version}-trixie@sha256:1bcff4befb740599103a2c7cb51058e14479b2e35e3a34a3f0dc4ede09927488"
node_builder_image="node:24-alpine3.24@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd"
runtime_image="alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
rust_target=""
rust_target_cpu=""
rust_builder_stage="builder-native"
rust_build_cache_key=""
oxibelt_version="${OXIBELT_DOCKER_IMAGE_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "${repo_root}/Cargo.toml" | head -n 1)}"
oxibelt_revision="${OXIBELT_DOCKER_IMAGE_REVISION:-$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || true)}"
oxibelt_source_tree="${OXIBELT_DOCKER_IMAGE_SOURCE_TREE:-}"
oxibelt_created="${OXIBELT_DOCKER_IMAGE_CREATED:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
oxibelt_source="${OXIBELT_DOCKER_IMAGE_SOURCE:-$(detect_oxibelt_source)}"
oxibelt_ref_name="${OXIBELT_DOCKER_IMAGE_REF_NAME:-${oxibelt_version}}"

case "${artifact_arch}" in
  amd64v2)
    if [[ "${platform}" != "linux/amd64" ]]; then
      usage
      exit 2
    fi
    rust_target="x86_64-unknown-linux-musl"
    rust_target_cpu="x86-64-v2"
    rust_build_cache_key="x86_64-musl-x86-64-v2"
    ;;
  amd64)
    if [[ "${platform}" != "linux/amd64" ]]; then
      usage
      exit 2
    fi
    rust_target="x86_64-unknown-linux-musl"
    rust_target_cpu="x86-64-v3"
    rust_build_cache_key="x86_64-musl-x86-64-v3"
    ;;
  amd64v4)
    if [[ "${platform}" != "linux/amd64" ]]; then
      usage
      exit 2
    fi
    rust_target="x86_64-unknown-linux-musl"
    rust_target_cpu="x86-64-v4"
    rust_build_cache_key="x86_64-musl-x86-64-v4"
    ;;
  arm64)
    if [[ "${platform}" != "linux/arm64" ]]; then
      usage
      exit 2
    fi
    rust_target="aarch64-unknown-linux-musl"
    rust_build_cache_key="aarch64-musl-native"
    ;;
  riscv64)
    if [[ "${platform}" != "linux/riscv64" ]]; then
      usage
      exit 2
    fi
    rust_target="riscv64gc-unknown-linux-musl"
    rust_builder_stage="builder-riscv64"
    rust_build_cache_key="riscv64gc-musl-cross-rs-c12165aa"
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ -z "${oxibelt_version}" ]]; then
  oxibelt_version="0.0.0"
fi

if [[ -z "${oxibelt_revision}" ]]; then
  oxibelt_revision="unknown"
fi

if [[ -z "${oxibelt_source_tree}" && "${oxibelt_revision}" =~ ^[0-9a-f]{40}$ ]]; then
  oxibelt_source_tree="$(git -C "${repo_root}" rev-parse "${oxibelt_revision}^{tree}" 2>/dev/null || true)"
fi

if [[ ! "${oxibelt_source_tree}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "A full lowercase source tree is required for rebuild evidence: ${oxibelt_source_tree}" >&2
  exit 2
fi

if [[ -z "${oxibelt_source}" ]]; then
  oxibelt_source="${default_oxibelt_source}"
fi

mkdir -p "${output_dir}"

cleanup_temporary_metadata() {
  if [[ -n "${build_metadata_tmp}" ]]; then
    rm -f -- "${build_metadata_tmp}"
  fi
}
trap cleanup_temporary_metadata EXIT

build_metadata_tmp="$(mktemp "${build_metadata}.tmp.XXXXXX")"
rm -f -- "${build_metadata_tmp}"

docker buildx build \
  --platform "${platform}" \
  --file "${repo_root}/source/ops/Dockerfile.alpine" \
  --build-arg "RUST_BUILDER_IMAGE=${rust_builder_image}" \
  --build-arg "OXIBELT_NODE_IMAGE=${node_builder_image}" \
  --build-arg "OXIBELT_RUNTIME_IMAGE=${runtime_image}" \
  --build-arg "OXIBELT_RUST_BUILDER_STAGE=${rust_builder_stage}" \
  --build-arg "OXIBELT_RUST_CACHE_ID=${rust_build_cache_key}" \
  --build-arg "OXIBELT_RUST_TARGET=${rust_target}" \
  --build-arg "OXIBELT_RUST_TARGET_CPU=${rust_target_cpu}" \
  --build-arg "OXIBELT_VERSION=${oxibelt_version}" \
  --build-arg "OXIBELT_REVISION=${oxibelt_revision}" \
  --build-arg "OXIBELT_CREATED=${oxibelt_created}" \
  --build-arg "OXIBELT_SOURCE=${oxibelt_source}" \
  --build-arg "OXIBELT_REF_NAME=${oxibelt_ref_name}" \
  --target "${role}" \
  --tag "${image_tag}" \
  --metadata-file "${build_metadata_tmp}" \
  --output "type=docker,dest=${image_tar}" \
  "${repo_root}"

mv -- "${build_metadata_tmp}" "${build_metadata}"

python3 "${repo_root}/tests/scripts/validate-ci-image-artifact.py" create \
  --image-tar "${image_tar}" \
  --build-metadata "${build_metadata}" \
  --contract "${artifact_contract}" \
  --role "${role}" \
  --artifact-arch "${artifact_arch}" \
  --expected-revision "${oxibelt_revision}" \
  --expected-source "${oxibelt_source}" \
  --expected-source-tree "${oxibelt_source_tree}" \
  --expected-version "${oxibelt_version}" \
  --expected-ref-name "${oxibelt_ref_name}" \
  --expected-created "${oxibelt_created}" \
  --rust-builder-image "${rust_builder_image}" \
  --node-builder-image "${node_builder_image}" \
  --runtime-image "${runtime_image}" \
  --repo-root "${repo_root}"

echo "Wrote ${image_tar}"
echo "Wrote ${build_metadata}"
echo "Wrote ${artifact_contract}"
