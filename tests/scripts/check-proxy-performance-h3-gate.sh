#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

artifact_root="${OXIBELT_TEST_ARTIFACT_DIR:-}"
remove_artifact_root=0
if [[ -z "${artifact_root}" ]]; then
  artifact_root="$(mktemp -d)"
  remove_artifact_root=1
fi

run_artifact_dir="${artifact_root}/h3-gate-negative"
output_file="${artifact_root}/h3-gate-negative.log"

cleanup() {
  if [[ "${remove_artifact_root}" == "1" ]]; then
    rm -rf "${artifact_root}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "${run_artifact_dir}"

status=0
OXIBELT_TEST_ARTIFACT_DIR="${run_artifact_dir}" \
OXIBELT_PERF_OXIBELT_BASELINE_SCENARIO=baseline-no-http3 \
OXIBELT_PERF_DURATION_SECONDS="${OXIBELT_PERF_DURATION_SECONDS:-1}" \
OXIBELT_PERF_WARMUP_SECONDS="${OXIBELT_PERF_WARMUP_SECONDS:-0}" \
OXIBELT_PERF_CONCURRENCY="${OXIBELT_PERF_CONCURRENCY:-1}" \
OXIBELT_PERF_SOAK_SECONDS="${OXIBELT_PERF_SOAK_SECONDS:-1}" \
  "${repo_root}/tests/scripts/run-proxy-performance.sh" --profile smoke --comparators oxibelt \
  >"${output_file}" 2>&1 || status=$?

if [[ "${status}" == "0" ]]; then
  cat "${output_file}" >&2
  echo "expected mandatory OxiBelt HTTP/3 performance gate to fail" >&2
  exit 1
fi

if ! grep -F "mandatory HTTP/3 probe failed for oxibelt" "${output_file}" >/dev/null; then
  cat "${output_file}" >&2
  echo "expected mandatory HTTP/3 diagnostic was not emitted" >&2
  exit 1
fi

results_json="${run_artifact_dir}/results.json"
if [[ -f "${results_json}" ]] &&
  jq -e '.[] | select(.label == "oxibelt-h3" and (.skipped // false))' "${results_json}" >/dev/null; then
  cat "${results_json}" >&2
  echo "mandatory OxiBelt HTTP/3 failure must not be recorded as skipped" >&2
  exit 1
fi

echo "Mandatory OxiBelt HTTP/3 performance gate failed closed as expected"
