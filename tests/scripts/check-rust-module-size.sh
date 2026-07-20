#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
source_roots=(
  "${repo_root}/source/src"
  "${repo_root}/source/apps"
  "${repo_root}/source/crates"
)
max_lines="${OXIBELT_RUST_SOURCE_LINE_LIMIT:-750}"

checked=0
violations=0

while IFS= read -r file; do
  checked=$((checked + 1))
  rel_path="${file#"${repo_root}/"}"
  line_count="$(wc -l < "${file}")"
  line_count="${line_count//[[:space:]]/}"

  if (( line_count <= max_lines )); then
    continue
  fi

  echo "Rust source file exceeds the modularization threshold:" >&2
  printf '  %s: %s lines (target %s)\n' \
    "${rel_path}" "${line_count}" "${max_lines}" >&2

  violations=$((violations + 1))
done < <(find "${source_roots[@]}" -type f -name '*.rs' | sort)

if (( violations > 0 )); then
  cat >&2 <<EOF

Split oversized Rust files by responsibility before merging.
EOF
  exit 1
fi

echo "Rust module size check passed for ${checked} files (limit: ${max_lines} lines)."
