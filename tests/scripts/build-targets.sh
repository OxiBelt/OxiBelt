#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
crate_root="${repo_root}/source"

host_triple="$(rustc -Vv | sed -n 's/^host: //p')"

case "${host_triple}" in
  x86_64-unknown-linux-gnu)
    gnu_target="${host_triple}"
    musl_target="x86_64-unknown-linux-musl"
    ;;
  aarch64-unknown-linux-gnu)
    gnu_target="${host_triple}"
    musl_target="aarch64-unknown-linux-musl"
    ;;
  riscv64gc-unknown-linux-gnu)
    gnu_target="${host_triple}"
    musl_target="riscv64gc-unknown-linux-musl"
    ;;
  x86_64-unknown-linux-musl|aarch64-unknown-linux-musl|riscv64gc-unknown-linux-musl)
    musl_target="${host_triple}"
    gnu_target="${host_triple/-unknown-linux-musl/-unknown-linux-gnu}"
    ;;
  *)
    echo "unsupported Linux host triple: ${host_triple}" >&2
    exit 1
    ;;
esac

echo "Installing Rust targets: ${gnu_target} ${musl_target}"
rustup target add "${gnu_target}" "${musl_target}"

if [[ "${musl_target}" == "x86_64-unknown-linux-musl" ]] && command -v musl-gcc >/dev/null 2>&1; then
  export CC_x86_64_unknown_linux_musl="musl-gcc"
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="musl-gcc"
fi

if [[ "${gnu_target}" == "riscv64gc-unknown-linux-gnu" ]] && command -v riscv64-linux-gnu-gcc >/dev/null 2>&1; then
  export CC_riscv64gc_unknown_linux_gnu="riscv64-linux-gnu-gcc"
  export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="riscv64-linux-gnu-gcc"
fi

if [[ "${musl_target}" == "riscv64gc-unknown-linux-musl" ]]; then
  if [[ -z "${CC_riscv64gc_unknown_linux_musl:-}" ]]; then
    if command -v riscv64-linux-musl-gcc >/dev/null 2>&1; then
      export CC_riscv64gc_unknown_linux_musl="riscv64-linux-musl-gcc"
    elif [[ "${host_triple}" == "riscv64gc-unknown-linux-musl" ]]; then
      export CC_riscv64gc_unknown_linux_musl="cc"
    fi
  fi

  if [[ -n "${CC_riscv64gc_unknown_linux_musl:-}" ]] && [[ -z "${CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_MUSL_LINKER:-}" ]]; then
    export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_MUSL_LINKER="${CC_riscv64gc_unknown_linux_musl}"
  fi

  if [[ -z "${CC_riscv64gc_unknown_linux_musl:-}" ]]; then
    echo "riscv64gc-unknown-linux-musl requires riscv64-linux-musl-gcc (or CC_riscv64gc_unknown_linux_musl)." >&2
    exit 1
  fi

  if ! command -v clang >/dev/null 2>&1; then
    echo "warning: clang was not found; aws-lc-rs bindgen for ${musl_target} may fail without clang/libclang." >&2
  fi
fi

echo "Building ${gnu_target}"
(cd "${crate_root}" && cargo build --locked --release --target "${gnu_target}")

echo "Building ${musl_target}"
(cd "${crate_root}" && cargo build --locked --release --target "${musl_target}")
