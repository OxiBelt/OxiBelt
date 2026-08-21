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
tool_root="$(cd -- "${script_dir}/../.." && pwd)"
source_root="${OXIBELT_DOCKER_IMAGE_SOURCE_ROOT:-${tool_root}}"
if [[ ! -d "${source_root}" ]]; then
  echo "Docker image source root is not an existing directory" >&2
  exit 2
fi
repo_root="$(cd -- "${source_root}" && pwd -P)"
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
rust_toolchain_version="1.98.0"
rust_builder_image="rust:${rust_toolchain_version}-trixie@sha256:7f7a53a25a0319dd8284e279d529d45759cb384d59b14cc6806132910f45522e"
node_builder_image="node:24-alpine3.24@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43"
runtime_image="alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
rust_target=""
amd64_target_cpu=""
rust_builder_stage="builder-native"
rust_build_cache_key=""
derived_revision="$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || true)"
derived_dirty="unknown"
derived_kind="source_archive"
derived_ref="unknown"
derived_version="0.0.0-dev.archive"
if [[ "${derived_revision}" =~ ^[0-9a-f]{40}$ ]]; then
  derived_dirty="clean"
  if ! git -C "${repo_root}" diff --quiet --ignore-submodules -- ||
     ! git -C "${repo_root}" diff --cached --quiet --ignore-submodules --; then
    derived_dirty="dirty"
  fi
  derived_ref="$(git -C "${repo_root}" symbolic-ref -q HEAD 2>/dev/null || true)"
  [[ -n "${derived_ref}" ]] || derived_ref="unknown"
  mapfile -t exact_release_tags < <(
    git -C "${repo_root}" tag --points-at HEAD 2>/dev/null |
      sed -nE '/^[0-9]+\.[0-9]+\.[0-9]+(-beta\.[0-9]+|-build\.[0-9a-f]{8})?$/p'
  )
  for release_tag in "${exact_release_tags[@]}"; do
    if [[ "${release_tag}" =~ -build\.([0-9a-f]{8})$ ]] &&
       [[ "${BASH_REMATCH[1]}" != "${derived_revision:0:8}" ]]; then
      echo "release build tag does not match the source revision" >&2
      exit 2
    fi
  done
  if [[ "${#exact_release_tags[@]}" -gt 0 ]]; then
    release_tag="$(printf '%s\n' "${exact_release_tags[@]}" | python3 -c '
import re, sys
def key(value):
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:-(beta)\.([0-9]+)|-(build)\.([0-9a-f]{8}))?", value)
    if match is None:
        raise SystemExit("invalid release tag passed to selector")
    base = tuple(map(int, match.group(1, 2, 3)))
    if match.group(4) is not None:
        return (*base, 0, "beta", int(match.group(5)))
    if match.group(6) is not None:
        return (*base, 0, "build", match.group(7))
    return (*base, 1, "", 0)
values = [line.rstrip("\n") for line in sys.stdin if line.rstrip("\n")]
print(max(values, key=key))
')"
    derived_kind="tagged_development"
    derived_ref="refs/tags/${release_tag}"
    derived_version="${release_tag}"
  else
    derived_kind="git_development"
    derived_version="0.0.0-dev.g${derived_revision:0:8}"
  fi
  if [[ "${derived_dirty}" == "dirty" ]]; then
    derived_version="${derived_version}+dirty"
  fi
fi

oxibelt_version="${OXIBELT_DOCKER_IMAGE_VERSION:-${derived_version}}"
oxibelt_revision="${OXIBELT_DOCKER_IMAGE_REVISION:-${derived_revision:-unknown}}"
oxibelt_source_ref="${OXIBELT_DOCKER_IMAGE_SOURCE_REF:-${derived_ref}}"
oxibelt_source_dirty="${OXIBELT_DOCKER_IMAGE_SOURCE_DIRTY:-${derived_dirty}}"
oxibelt_build_kind="${OXIBELT_DOCKER_IMAGE_BUILD_KIND:-${derived_kind}}"
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
    amd64_target_cpu="x86-64-v2"
    rust_build_cache_key="x86_64-musl-x86-64-v2"
    ;;
  amd64)
    if [[ "${platform}" != "linux/amd64" ]]; then
      usage
      exit 2
    fi
    rust_target="x86_64-unknown-linux-musl"
    amd64_target_cpu="x86-64-v3"
    rust_build_cache_key="x86_64-musl-x86-64-v3"
    ;;
  amd64v4)
    if [[ "${platform}" != "linux/amd64" ]]; then
      usage
      exit 2
    fi
    rust_target="x86_64-unknown-linux-musl"
    amd64_target_cpu="x86-64-v4"
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
    rust_build_cache_key="riscv64gc-musl-cross-rs-60372bf6"
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ -z "${oxibelt_revision}" ]]; then
  oxibelt_revision="unknown"
fi

if [[ ! "${oxibelt_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] ||
   [[ ! "${oxibelt_source_dirty}" =~ ^(clean|dirty|unknown)$ ]] ||
   [[ ! "${oxibelt_build_kind}" =~ ^(official_release|tagged_development|git_development|source_archive)$ ]]; then
  echo "the Docker build identity tuple is malformed" >&2
  exit 2
fi
if [[ ! "${oxibelt_created}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
  echo "the Docker image creation time must be second-resolution UTC RFC 3339" >&2
  exit 2
fi
if ! source_date_epoch="$(
  python3 -c '
import datetime
import sys

try:
    created = datetime.datetime.strptime(sys.argv[1], "%Y-%m-%dT%H:%M:%SZ")
except ValueError:
    raise SystemExit(1)
created = created.replace(tzinfo=datetime.timezone.utc)
epoch = int(created.timestamp())
if epoch < 0:
    raise SystemExit(1)
print(epoch)
' "${oxibelt_created}"
)"; then
  echo "the Docker image creation time is not a supported UTC timestamp" >&2
  exit 2
fi
if [[ "${oxibelt_source_ref}" != "unknown" ]] &&
   [[ ! "${oxibelt_source_ref}" =~ ^refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]]; then
  echo "the Docker build source ref is malformed" >&2
  exit 2
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
  --build-arg "OXIBELT_AMD64_TARGET_CPU=${amd64_target_cpu}" \
  --build-arg "OXIBELT_BUILD_VERSION=${oxibelt_version}" \
  --build-arg "OXIBELT_BUILD_REVISION=${oxibelt_revision}" \
  --build-arg "OXIBELT_BUILD_REF=${oxibelt_source_ref}" \
  --build-arg "OXIBELT_BUILD_DIRTY=${oxibelt_source_dirty}" \
  --build-arg "OXIBELT_BUILD_KIND=${oxibelt_build_kind}" \
  --build-arg "OXIBELT_CREATED=${oxibelt_created}" \
  --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
  --build-arg "OXIBELT_SOURCE=${oxibelt_source}" \
  --build-arg "OXIBELT_REF_NAME=${oxibelt_ref_name}" \
  --target "${role}" \
  --tag "${image_tag}" \
  --metadata-file "${build_metadata_tmp}" \
  --output "type=docker,dest=${image_tar},rewrite-timestamp=true" \
  "${repo_root}"

mv -- "${build_metadata_tmp}" "${build_metadata}"

python3 "${tool_root}/tests/scripts/validate-ci-image-artifact.py" create \
  --image-tar "${image_tar}" \
  --build-metadata "${build_metadata}" \
  --contract "${artifact_contract}" \
  --role "${role}" \
  --artifact-arch "${artifact_arch}" \
  --expected-revision "${oxibelt_revision}" \
  --expected-source "${oxibelt_source}" \
  --expected-source-tree "${oxibelt_source_tree}" \
  --expected-version "${oxibelt_version}" \
  --expected-source-ref "${oxibelt_source_ref}" \
  --expected-source-dirty "${oxibelt_source_dirty}" \
  --expected-build-kind "${oxibelt_build_kind}" \
  --expected-ref-name "${oxibelt_ref_name}" \
  --expected-created "${oxibelt_created}" \
  --rust-builder-image "${rust_builder_image}" \
  --node-builder-image "${node_builder_image}" \
  --runtime-image "${runtime_image}" \
  --repo-root "${repo_root}"

echo "Wrote ${image_tar}"
echo "Wrote ${build_metadata}"
echo "Wrote ${artifact_contract}"
