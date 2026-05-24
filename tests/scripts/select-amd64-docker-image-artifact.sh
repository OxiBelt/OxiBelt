#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 auto|x86-64-v2|x86-64-v3|x86-64-v4 [--allow-unsupported]" >&2
}

mode="${1:-}"
allow_unsupported="${OXIBELT_AMD64_ALLOW_UNSUPPORTED:-0}"
if [[ "${2:-}" == "--allow-unsupported" ]]; then
  allow_unsupported=1
elif [[ -n "${2:-}" ]]; then
  usage
  exit 2
fi

if [[ -z "${mode}" ]]; then
  usage
  exit 2
fi

cpu_flags="$(
  awk '
    /^flags[[:space:]]*:/ {
      sub(/^[^:]*:[[:space:]]*/, "")
      print
    }
  ' /proc/cpuinfo 2>/dev/null | tr '\n' ' '
)"

if [[ -z "${cpu_flags}" ]]; then
  echo "failed to read CPU flags from /proc/cpuinfo" >&2
  exit 2
fi

has_flag() {
  local flag="$1"
  [[ " ${cpu_flags} " == *" ${flag} "* ]]
}

missing_features=()

require_any() {
  local feature_name="$1"
  shift
  local flag
  for flag in "$@"; do
    if has_flag "${flag}"; then
      return 0
    fi
  done
  missing_features+=("${feature_name}")
}

supports_target() {
  local target="$1"
  missing_features=()

  case "${target}" in
    x86-64-v2|x86-64-v3|x86-64-v4) ;;
    *)
      echo "unsupported AMD64 target CPU: ${target}" >&2
      exit 2
      ;;
  esac

  require_any cx16 cx16
  require_any lahf_lm lahf_lm
  require_any popcnt popcnt
  require_any sse3 pni sse3
  require_any ssse3 ssse3
  require_any sse4_1 sse4_1
  require_any sse4_2 sse4_2

  if [[ "${target}" == "x86-64-v3" || "${target}" == "x86-64-v4" ]]; then
    require_any avx avx
    require_any avx2 avx2
    require_any bmi1 bmi1
    require_any bmi2 bmi2
    require_any f16c f16c
    require_any fma fma
    require_any lzcnt lzcnt abm
    require_any movbe movbe
    require_any xsave xsave
  fi

  if [[ "${target}" == "x86-64-v4" ]]; then
    require_any avx512f avx512f
    require_any avx512bw avx512bw
    require_any avx512cd avx512cd
    require_any avx512dq avx512dq
    require_any avx512vl avx512vl
  fi

  ((${#missing_features[@]} == 0))
}

select_auto_target() {
  local target
  for target in x86-64-v4 x86-64-v3 x86-64-v2; do
    if supports_target "${target}"; then
      echo "${target}"
      return 0
    fi
  done

  echo "runner CPU does not support x86-64-v2 or newer AMD64 Docker artifacts" >&2
  exit 1
}

emit_output() {
  local key="$1"
  local value="$2"
  echo "${key}=${value}"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "${key}=${value}" >>"${GITHUB_OUTPUT}"
  fi
}

target_cpu=""
case "${mode}" in
  auto)
    target_cpu="$(select_auto_target)"
    ;;
  x86-64-v2|x86-64-v3|x86-64-v4)
    target_cpu="${mode}"
    ;;
  *)
    usage
    exit 2
    ;;
esac

supported=true
if ! supports_target "${target_cpu}"; then
  supported=false
  if [[ "${allow_unsupported}" != "1" ]]; then
    printf 'runner CPU does not support %s; missing: %s\n' \
      "${target_cpu}" \
      "$(IFS=,; echo "${missing_features[*]}")" >&2
    exit 1
  fi
fi

case "${target_cpu}" in
  x86-64-v2)
    artifact_arch="amd64v2"
    artifact_name="oxibelt-alpine-musl-amd64v2-image"
    image_tag="oxibelt:alpine-musl-amd64v2"
    image_tar="oxibelt-alpine-musl-amd64v2.tar"
    ;;
  x86-64-v3)
    artifact_arch="amd64"
    artifact_name="oxibelt-alpine-musl-amd64-image"
    image_tag="oxibelt:alpine-musl-amd64"
    image_tar="oxibelt-alpine-musl-amd64.tar"
    ;;
  x86-64-v4)
    artifact_arch="amd64v4"
    artifact_name="oxibelt-alpine-musl-amd64v4-image"
    image_tag="oxibelt:alpine-musl-amd64v4"
    image_tar="oxibelt-alpine-musl-amd64v4.tar"
    ;;
esac

emit_output supported "${supported}"
emit_output target_cpu "${target_cpu}"
emit_output artifact_arch "${artifact_arch}"
emit_output artifact_name "${artifact_name}"
emit_output image_tag "${image_tag}"
emit_output image_tar "${image_tar}"
emit_output missing_features "$(IFS=,; echo "${missing_features[*]}")"
