#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
variant="${1:-default}"
if [[ $# -gt 0 ]]; then
  shift
fi

usage() {
  cat >&2 <<'EOF'
Usage: tests/scripts/build-crypto-backend-variant.sh <variant> [cargo command...]

Variants:
  default          Run Cargo without forcing RustCrypto dependency backends.
  software         Force RustCrypto SHA2, AES, and ChaCha20 software backends.
  x86-hardware     Force x86 SHA, AES AVX256, and ChaCha20 AVX2 backends.
  x86-avx512       Force x86 SHA, AES AVX512, and ChaCha20 AVX512 backends.

When no cargo command is supplied, the script runs:
  cargo check --all-targets --locked
EOF
}

require_cpu_flags() {
  local missing=()
  local flags
  flags="$(awk -F: '/^flags[[:space:]]*:/ { print $2; exit }' /proc/cpuinfo 2>/dev/null || true)"
  for flag in "$@"; do
    if [[ " ${flags} " != *" ${flag} "* ]]; then
      missing+=("${flag}")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    printf 'CPU is missing required feature(s) for %s: %s\n' "${variant}" "${missing[*]}" >&2
    exit 1
  fi
}

variant_rustflags=()
case "${variant}" in
  default)
    ;;
  software)
    variant_rustflags=(
      '--cfg=sha2_backend="soft"'
      '--cfg=aes_backend="soft"'
      '--cfg=chacha20_backend="soft"'
    )
    ;;
  x86-hardware)
    require_cpu_flags sha aes avx vaes avx2
    variant_rustflags=(
      '-Ctarget-feature=+sha,+avx2'
      '--cfg=sha2_256_backend="x86-sha"'
      '--cfg=aes_backend="avx256"'
      '--cfg=chacha20_backend="avx2"'
    )
    ;;
  x86-avx512)
    require_cpu_flags sha vaes avx512f avx512vl
    variant_rustflags=(
      '-Ctarget-feature=+sha,+avx512f,+avx512vl,+vaes'
      '--cfg=sha2_256_backend="x86-sha"'
      '--cfg=aes_backend="avx512"'
      '--cfg' 'chacha20_avx512'
      '--cfg=chacha20_backend="avx512"'
    )
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage
    printf '\nUnknown crypto backend variant: %s\n' "${variant}" >&2
    exit 2
    ;;
esac

cmd=("$@")
if (( ${#cmd[@]} == 0 )); then
  cmd=(cargo check --all-targets --locked)
fi

existing_rustflags="${RUSTFLAGS:-}"
variant_rustflags_joined="${variant_rustflags[*]}"
if [[ -n "${existing_rustflags}" && -n "${variant_rustflags_joined}" ]]; then
  export RUSTFLAGS="${existing_rustflags} ${variant_rustflags_joined}"
elif [[ -n "${variant_rustflags_joined}" ]]; then
  export RUSTFLAGS="${variant_rustflags_joined}"
else
  export RUSTFLAGS="${existing_rustflags}"
fi

cd "${repo_root}"
exec "${cmd[@]}"
