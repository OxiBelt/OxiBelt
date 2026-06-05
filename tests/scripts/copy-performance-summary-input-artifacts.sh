#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: tests/scripts/copy-performance-summary-input-artifacts.sh <source-dir> <destination-dir>

Copies only the small Docker performance files needed by the summary
aggregator. Raw profiling evidence, logs, probe output, generated configs, and
external tool output remain in the full diagnostic artifact.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$#" -ne 2 ]]; then
  usage
  exit 64
fi

source_dir="${1%/}"
destination_dir="${2%/}"

if [[ ! -d "${source_dir}" ]]; then
  printf 'Docker performance summary input source does not exist: %s\n' "${source_dir}" >&2
  exit 0
fi

mkdir -p "${destination_dir}"

copy_summary_file_name() {
  local file_name="$1"
  local source_file relative_path destination_file

  while IFS= read -r -d '' source_file; do
    relative_path="${source_file#${source_dir}/}"
    destination_file="${destination_dir}/${relative_path}"
    mkdir -p "$(dirname "${destination_file}")"
    cp "${source_file}" "${destination_file}"
  done < <(find "${source_dir}" -type f -name "${file_name}" -print0)
}

for file_name in \
  results.json \
  external-results.json \
  profile-results.json \
  iteration-status.json \
  unsupported-cpu.json
do
  copy_summary_file_name "${file_name}"
done
