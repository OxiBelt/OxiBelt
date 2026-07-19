#!/bin/sh
set -eu

binary="${1:-}"
rust_target="${2:-}"
label="${3:-release binary}"

if [ -z "${binary}" ] || [ -z "${rust_target}" ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 <binary> <rust-target> [label]" >&2
  exit 2
fi

if [ ! -f "${binary}" ] || [ ! -x "${binary}" ]; then
  echo "${label} is missing or is not executable: ${binary}" >&2
  exit 1
fi

case "${rust_target}" in
  x86_64-unknown-linux-musl)
    expected_machine="Advanced Micro Devices X86-64"
    ;;
  aarch64-unknown-linux-musl)
    expected_machine="AArch64"
    ;;
  riscv64gc-unknown-linux-musl)
    expected_machine="RISC-V"
    ;;
  *)
    echo "unsupported Rust target for ELF validation: ${rust_target}" >&2
    exit 2
    ;;
esac

elf_class="$(readelf -hW "${binary}" | awk -F: '$1 ~ /^[[:space:]]*Class[[:space:]]*$/ { sub(/^[[:space:]]*/, "", $2); print $2 }')"
if [ "${elf_class}" != "ELF64" ]; then
  echo "ELF class for ${binary} was ${elf_class:-missing}, expected ELF64" >&2
  exit 1
fi

elf_machine="$(readelf -hW "${binary}" | awk -F: '$1 ~ /^[[:space:]]*Machine[[:space:]]*$/ { sub(/^[[:space:]]*/, "", $2); print $2 }')"
if [ "${elf_machine}" != "${expected_machine}" ]; then
  echo "ELF machine for ${binary} was ${elf_machine:-missing}, expected ${expected_machine}" >&2
  exit 1
fi

if readelf -lW "${binary}" | grep -Eq '[[:space:]]INTERP[[:space:]]'; then
  echo "${label} must be statically linked: PT_INTERP is present" >&2
  exit 1
fi

if readelf -dW "${binary}" | grep -Fq '(NEEDED)'; then
  echo "${label} must be statically linked: DT_NEEDED is present" >&2
  exit 1
fi

