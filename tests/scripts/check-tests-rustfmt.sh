#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

mapfile -t tracked_rust_files < <(git ls-files 'tests/**/*.rs')

rust_2024_files=()
rust_2021_files=()
unknown_files=()

for file in "${tracked_rust_files[@]}"; do
  case "${file}" in
    tests/rust/*.rs)
      rust_2024_files+=("${file}")
      ;;
    tests/docker/*.rs)
      rust_2021_files+=("${file}")
      ;;
    *)
      unknown_files+=("${file}")
      ;;
  esac
done

if ((${#unknown_files[@]} > 0)); then
  printf 'error: assign a rustfmt edition for these test Rust files:\n' >&2
  printf '  %s\n' "${unknown_files[@]}" >&2
  exit 1
fi

if ((${#rust_2024_files[@]} > 0)); then
  rustfmt \
    --check \
    --edition 2024 \
    --config-path tests/rustfmt.toml \
    --config skip_children=true \
    "${rust_2024_files[@]}"
fi

if ((${#rust_2021_files[@]} > 0)); then
  rustfmt \
    --check \
    --edition 2021 \
    --config-path tests/rustfmt.toml \
    --config skip_children=true \
    "${rust_2021_files[@]}"
fi
