#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tests/scripts/build-performance-comparator-image-artifact.sh nginx|caddy|openresty <docker-platform> x86-64-v2|x86-64-v3 <output-dir>
EOF
}

comparator="${1:-}"
platform="${2:-}"
target_cpu="${3:-}"
output_dir="${4:-}"

if [[ -z "${comparator}" || -z "${platform}" || -z "${target_cpu}" || -z "${output_dir}" ]]; then
  usage
  exit 2
fi

if [[ "${platform}" != "linux/amd64" ]]; then
  usage
  exit 2
fi

case "${target_cpu}" in
  x86-64-v2|x86-64-v3) ;;
  *)
    usage
    exit 2
    ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
dockerfile=""
image_tag="oxibelt/performance-${comparator}:alpine-${target_cpu}"
image_tar="${output_dir%/}/oxibelt-performance-${comparator}-${target_cpu}.tar"

case "${comparator}" in
  nginx)
    dockerfile="${repo_root}/tests/docker/performance_comparators/Dockerfile.nginx"
    build_args=(
      --build-arg "NGINX_VERSION=1.31.3"
      --build-arg "NGINX_TARGET_CPU=${target_cpu}"
    )
    ;;
  caddy)
    dockerfile="${repo_root}/tests/docker/performance_comparators/Dockerfile.caddy"
    build_args=(
      --build-arg "CADDY_VERSION=2.11.4"
      --build-arg "CADDY_TARGET_CPU=${target_cpu}"
    )
    ;;
  openresty)
    dockerfile="${repo_root}/tests/docker/performance_comparators/Dockerfile.openresty"
    build_args=(
      --build-arg "OPENRESTY_VERSION=1.31.1.1"
      --build-arg "OPENRESTY_IMAGE_VERSION=2"
      --build-arg "OPENRESTY_TARGET_CPU=${target_cpu}"
    )
    ;;
  *)
    usage
    exit 2
    ;;
esac

mkdir -p "${output_dir}"

docker buildx build \
  --platform "${platform}" \
  --file "${dockerfile}" \
  "${build_args[@]}" \
  --tag "${image_tag}" \
  --output "type=docker,dest=${image_tar}" \
  "${repo_root}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "image_tag=${image_tag}"
    echo "image_tar=$(basename "${image_tar}")"
  } >>"${GITHUB_OUTPUT}"
fi

echo "Wrote ${image_tar}"
