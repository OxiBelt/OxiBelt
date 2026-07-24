#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
  cat <<'EOF'
Usage: tests/scripts/check-rust-module-size.sh [--warn|--enforce]

  --warn     Report oversized Rust modules without failing (default).
  --enforce  Fail when a Rust module exceeds the configured line limit.
EOF
}

mode="warn"
if (( $# > 1 )); then
  echo "error: expected at most one mode argument" >&2
  usage >&2
  exit 2
fi

case "${1:-}" in
  "")
    ;;
  --warn)
    ;;
  --enforce)
    mode="enforce"
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    printf 'error: unsupported argument: %q\n' "$1" >&2
    usage >&2
    exit 2
    ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
source_roots=(
  "${repo_root}/source/src"
  "${repo_root}/source/apps"
  "${repo_root}/source/crates"
)
max_lines="${OXIBELT_RUST_SOURCE_LINE_LIMIT-750}"

if [[ ! "${max_lines}" =~ ^[1-9][0-9]*$ ]]; then
  printf \
    'error: OXIBELT_RUST_SOURCE_LINE_LIMIT must be a positive base-10 integer; got %q\n' \
    "${max_lines}" >&2
  exit 2
fi

for source_root in "${source_roots[@]}"; do
  if [[ ! -d "${source_root}" ]]; then
    printf 'error: required Rust source root is missing: %q\n' \
      "${source_root#"${repo_root}/"}" >&2
    exit 1
  fi
  if [[ ! -r "${source_root}" || ! -x "${source_root}" ]]; then
    printf 'error: required Rust source root is not readable: %q\n' \
      "${source_root#"${repo_root}/"}" >&2
    exit 1
  fi
done

file_list=""
if ! file_list="$(mktemp -- "${TMPDIR:-/tmp}/oxibelt-rust-source-files.XXXXXX")"; then
  echo "error: could not create the Rust source file list" >&2
  exit 1
fi

cleanup() {
  rm -f -- "${file_list}"
}
trap cleanup EXIT

if ! find "${source_roots[@]}" -type f -name '*.rs' -print0 \
  | LC_ALL=C sort -z > "${file_list}"; then
  echo "error: could not enumerate all Rust source files" >&2
  exit 1
fi

decimal_at_most() {
  local value="$1"
  local limit="$2"

  if (( ${#value} < ${#limit} )); then
    return 0
  fi
  if (( ${#value} > ${#limit} )); then
    return 1
  fi

  [[ "${value}" == "${limit}" || "${value}" < "${limit}" ]]
}

checked=0
violations=0

while IFS= read -r -d '' file; do
  rel_path="${file#"${repo_root}/"}"

  if [[ ! -f "${file}" ]]; then
    printf 'error: Rust source file disappeared or is no longer regular: %q\n' \
      "${rel_path}" >&2
    exit 1
  fi
  if ! file_mode="$(stat -c '%a' -- "${file}")"; then
    printf 'error: could not inspect Rust source file permissions: %q\n' \
      "${rel_path}" >&2
    exit 1
  fi
  if [[ ! "${file_mode}" =~ ^[0-7]{1,4}$ ]]; then
    printf 'error: invalid permissions returned for Rust source file: %q\n' \
      "${rel_path}" >&2
    exit 1
  fi
  if (( (8#${file_mode} & 0444) == 0 )) || [[ ! -r "${file}" ]]; then
    printf 'error: Rust source file is not readable: %q\n' "${rel_path}" >&2
    exit 1
  fi
  if ! line_count="$(wc -l < "${file}")"; then
    printf 'error: could not count lines in Rust source file: %q\n' \
      "${rel_path}" >&2
    exit 1
  fi
  if [[ ! "${line_count}" =~ ^[[:space:]]*[0-9]+[[:space:]]*$ ]]; then
    printf 'error: invalid line count returned for Rust source file: %q\n' \
      "${rel_path}" >&2
    exit 1
  fi
  line_count="${line_count//[[:space:]]/}"

  checked=$((checked + 1))

  if decimal_at_most "${line_count}" "${max_lines}"; then
    continue
  fi

  echo "Rust source file exceeds the modularization threshold:" >&2
  printf '  %q: %s lines (target %s)\n' \
    "${rel_path}" "${line_count}" "${max_lines}" >&2

  violations=$((violations + 1))
done < "${file_list}"

if (( checked == 0 )); then
  echo "error: no Rust source files were found in the required source roots" >&2
  exit 1
fi

if (( violations > 0 )); then
  if [[ "${mode}" == "enforce" ]]; then
    cat >&2 <<EOF

Split oversized Rust files by responsibility before merging.
EOF
    exit 1
  fi

  printf \
    '\nRust module size advisory: %s file(s) exceeded %s lines; continuing in --warn mode.\n' \
    "${violations}" "${max_lines}" >&2
  exit 0
fi

echo "Rust module size check passed for ${checked} files (limit: ${max_lines} lines)."
