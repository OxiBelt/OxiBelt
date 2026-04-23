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

echo "Building ${gnu_target}"
(cd "${crate_root}" && cargo build --locked --release --target "${gnu_target}")

echo "Building ${musl_target}"
(cd "${crate_root}" && cargo build --locked --release --target "${musl_target}")
