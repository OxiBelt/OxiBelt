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

grandfathered_limit() {
  case "$1" in
    source/src/cache.rs) echo "2688" ;;
    source/src/config.rs) echo "5806" ;;
    source/src/dynamic_policy.rs) echo "1049" ;;
    source/src/limits.rs) echo "1023" ;;
    source/src/proxy/http.rs) echo "3519" ;;
    source/src/proxy/http3.rs) echo "1112" ;;
    source/src/server.rs) echo "3210" ;;
    source/src/shared_state.rs) echo "2034" ;;
    source/src/upstream_discovery.rs) echo "942" ;;
    source/src/waf.rs) echo "5133" ;;
    source/src/waf/person_proof.rs) echo "868" ;;
    *) return 1 ;;
  esac
}

checked=0
grandfathered=0
violations=0

while IFS= read -r file; do
  checked=$((checked + 1))
  rel_path="${file#"${repo_root}/"}"
  line_count="$(wc -l < "${file}")"
  line_count="${line_count//[[:space:]]/}"

  if (( line_count <= max_lines )); then
    continue
  fi

  if baseline="$(grandfathered_limit "${rel_path}")"; then
    grandfathered=$((grandfathered + 1))
    if (( line_count <= baseline )); then
      continue
    fi

    echo "Rust source file grew past its modularization baseline:" >&2
    printf '  %s: %s lines (baseline %s, target %s)\n' \
      "${rel_path}" "${line_count}" "${baseline}" "${max_lines}" >&2
  else
    echo "Rust source file exceeds the modularization threshold:" >&2
    printf '  %s: %s lines (target %s)\n' \
      "${rel_path}" "${line_count}" "${max_lines}" >&2
  fi

  violations=$((violations + 1))
done < <(find "${source_roots[@]}" -type f -name '*.rs' | sort)

if (( violations > 0 )); then
  cat >&2 <<EOF

Split oversized Rust files by responsibility before merging.
Existing oversized files are grandfathered at their current size so they can be reduced incrementally, not grown.
If a grandfathered file is modularized below ${max_lines} lines, remove its entry from this script.
EOF
  exit 1
fi

echo "Rust module size check passed for ${checked} files (limit: ${max_lines} lines; ${grandfathered} grandfathered files)."
