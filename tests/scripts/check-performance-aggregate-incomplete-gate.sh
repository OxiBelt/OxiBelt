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

run_artifact_dir="${artifact_root}/oxibelt-docker-performance-smoke-static-files-shard-1/run-1"
comparison_dir="${artifact_root}/comparison"
performance_log="${artifact_root}/performance.log"
aggregate_log="${artifact_root}/aggregate.log"
report_json="${comparison_dir}/performance-comparison.json"

cleanup() {
  if [[ "${remove_artifact_root}" == "1" && "${KEEP_TEST_ARTIFACTS:-0}" != "1" ]]; then
    rm -rf "${artifact_root}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "${run_artifact_dir}" "${comparison_dir}"

status=0
OXIBELT_TEST_ARTIFACT_DIR="${run_artifact_dir}" \
OXIBELT_PERF_DURATION_SECONDS="${OXIBELT_PERF_DURATION_SECONDS:-1}" \
OXIBELT_PERF_WARMUP_SECONDS="${OXIBELT_PERF_WARMUP_SECONDS:-0}" \
OXIBELT_PERF_CONCURRENCY="${OXIBELT_PERF_CONCURRENCY:-1}" \
OXIBELT_PERF_SOAK_SECONDS="${OXIBELT_PERF_SOAK_SECONDS:-1}" \
  "${repo_root}/tests/scripts/run-proxy-performance.sh" \
    --profile smoke \
    --serving-type static-files \
    --comparators oxibelt \
  >"${performance_log}" 2>&1 || status=$?

if [[ "${status}" != "0" ]]; then
  cat "${performance_log}" >&2
  echo "expected focused OxiBelt-only static performance smoke to complete" >&2
  exit 1
fi

cargo run --quiet --locked -p oxibelt --bin oxibelt-performance-aggregate -- \
  --input-dir "${artifact_root}" \
  --output-dir "${comparison_dir}" \
  --profile smoke \
  --expected-runs 1 \
  >"${aggregate_log}" 2>&1

if [[ ! -f "${report_json}" ]]; then
  cat "${aggregate_log}" >&2
  echo "aggregate report was not written: ${report_json}" >&2
  exit 1
fi

gate_status="$(jq -r '.regression_gates.status // "unknown"' "${report_json}")"
if [[ "${gate_status}" != "fail" ]]; then
  cat "${report_json}" >&2
  echo "expected incomplete aggregate gate input to fail, got status '${gate_status}'" >&2
  exit 1
fi

if ! jq -e '
  .regression_gates.violations[]
  | select(
      .gate == "static_16k_h1c_min_caddy_ratio"
      and .scenario == "static-16k-h1c"
      and .metric == "median_rps"
      and .observed == null
      and .comparator == "caddy"
      and (.message | contains("missing Caddy static-16k-h1c median RPS"))
    )
' "${report_json}" >/dev/null; then
  cat "${report_json}" >&2
  echo "expected a missing Caddy static regression gate violation" >&2
  exit 1
fi

echo "Incomplete aggregate performance gate input failed closed as expected"
