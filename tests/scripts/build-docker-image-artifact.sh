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
build_metadata="${output_dir%/}/oxibelt-alpine-musl-${artifact_arch}-build-metadata.json"
build_inputs="${output_dir%/}/oxibelt-alpine-musl-${artifact_arch}-build-inputs.json"
build_metadata_tmp=""
build_inputs_tmp=""
rust_toolchain_version="1.96.0"
rust_builder_image="rust:${rust_toolchain_version}-trixie"
node_builder_image="node:24-alpine3.24"
runtime_image="alpine:3.24"
rust_target=""
rust_target_cpu=""
oxibelt_version="${OXIBELT_DOCKER_IMAGE_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "${repo_root}/source/Cargo.toml" | head -n 1)}"
oxibelt_revision="${OXIBELT_DOCKER_IMAGE_REVISION:-$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || true)}"
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
  arm64)
    if [[ "${platform}" != "linux/arm64" ]]; then
      usage
      exit 2
    fi
    rust_target="aarch64-unknown-linux-musl"
    ;;
  riscv64)
    if [[ "${platform}" != "linux/riscv64" ]]; then
      usage
      exit 2
    fi
    rust_target="riscv64gc-unknown-linux-musl"
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

if [[ -z "${oxibelt_source}" ]]; then
  oxibelt_source="${default_oxibelt_source}"
fi

mkdir -p "${output_dir}"

cleanup_temporary_metadata() {
  if [[ -n "${build_metadata_tmp}" ]]; then
    rm -f -- "${build_metadata_tmp}"
  fi
  if [[ -n "${build_inputs_tmp}" ]]; then
    rm -f -- "${build_inputs_tmp}"
  fi
}
trap cleanup_temporary_metadata EXIT

build_metadata_tmp="$(mktemp "${build_metadata}.tmp.XXXXXX")"
build_inputs_tmp="$(mktemp "${build_inputs}.tmp.XXXXXX")"
rm -f -- "${build_metadata_tmp}"

jq -n \
  --arg artifact_arch "${artifact_arch}" \
  --arg platform "${platform}" \
  --arg rust_toolchain_version "${rust_toolchain_version}" \
  --arg rust_target "${rust_target}" \
  --arg target_cpu "${rust_target_cpu}" \
  --arg rust_builder_image "${rust_builder_image}" \
  --arg node_builder_image "${node_builder_image}" \
  --arg runtime_image "${runtime_image}" \
  '{
    schemaVersion: 1,
    artifactArch: $artifact_arch,
    platform: $platform,
    rustToolchainVersion: $rust_toolchain_version,
    rustTarget: $rust_target,
    targetCpu: (if $target_cpu == "" then null else $target_cpu end),
    baseImages: [
      {
        buildArgument: "RUST_BUILDER_IMAGE",
        stage: "builder",
        reference: $rust_builder_image
      },
      {
        buildArgument: "OXIBELT_NODE_IMAGE",
        stage: "person-proof-ui",
        reference: $node_builder_image
      },
      {
        buildArgument: "OXIBELT_RUNTIME_IMAGE",
        stage: "runtime",
        reference: $runtime_image
      }
    ]
  }' >"${build_inputs_tmp}"

BUILDX_METADATA_PROVENANCE=max docker buildx build \
  --platform "${platform}" \
  --file "${repo_root}/source/ops/Dockerfile.alpine" \
  --build-arg "RUST_BUILDER_IMAGE=${rust_builder_image}" \
  --build-arg "OXIBELT_NODE_IMAGE=${node_builder_image}" \
  --build-arg "OXIBELT_RUNTIME_IMAGE=${runtime_image}" \
  --build-arg "OXIBELT_RUST_TARGET=${rust_target}" \
  --build-arg "OXIBELT_RUST_TARGET_CPU=${rust_target_cpu}" \
  --build-arg "OXIBELT_VERSION=${oxibelt_version}" \
  --build-arg "OXIBELT_REVISION=${oxibelt_revision}" \
  --build-arg "OXIBELT_CREATED=${oxibelt_created}" \
  --build-arg "OXIBELT_SOURCE=${oxibelt_source}" \
  --build-arg "OXIBELT_REF_NAME=${oxibelt_ref_name}" \
  --tag "${image_tag}" \
  --metadata-file "${build_metadata_tmp}" \
  --output "type=docker,dest=${image_tar}" \
  "${repo_root}"

mv -- "${build_metadata_tmp}" "${build_metadata}"
mv -- "${build_inputs_tmp}" "${build_inputs}"

echo "Wrote ${image_tar}"
echo "Wrote ${build_metadata}"
echo "Wrote ${build_inputs}"
