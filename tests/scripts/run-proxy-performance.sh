#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tests/scripts/run-proxy-performance.sh --profile smoke|benchmark|soak [--serving-type all|reverse-proxy|static-files|oxibelt-features|oxibelt-soak-stress|accept-multipliers] [--comparators oxibelt,nginx,caddy]

Environment:
  OXIBELT_DOCKER_IMAGE             OxiBelt image to test; built locally when unset
  OXIBELT_NGINX_IMAGE              nginx comparator image (default: nginx:mainline-alpine)
  OXIBELT_CADDY_IMAGE              Caddy comparator image (default: caddy:2-alpine)
  OXIBELT_PERF_DURATION_SECONDS    load duration override
  OXIBELT_PERF_WARMUP_SECONDS      warmup duration override
  OXIBELT_PERF_CONCURRENCY         load concurrency override
  OXIBELT_PERF_SOAK_SECONDS        soak duration override
  OXIBELT_PERF_MAX_P99_MS          sanity ceiling for load p99 latency
  OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION
                                      load request error budget per million completed requests
  OXIBELT_PERF_TCP_BASELINE_MAX_P50_MS
                                      OxiBelt H1/H2 baseline p50 latency ceiling
  OXIBELT_PERF_TCP_BASELINE_MAX_P99_MS
                                      OxiBelt H1/H2 baseline p99 latency ceiling
  OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO
                                      minimum OxiBelt/Caddy RPS ratio for static 16KiB H1C (default: 0.85)
  OXIBELT_PERF_WAF_ENFORCING_MIN_RPS
                                      minimum OxiBelt WAF enforcing RPS (default: 11000)
  OXIBELT_PERF_CRS_ENFORCING_MIN_RPS
                                      minimum OxiBelt CRS enforcing RPS (default: 9000)
  OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO
                                      maximum enforcing/monitor p99 ratio for WAF and CRS rows (default: 1.20)
  OXIBELT_PERF_OXIBELT_BASELINE_SCENARIO
                                      test-only OxiBelt baseline fixture override
  OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO
                                      test-only OxiBelt TLS handshake fixture override
  OXIBELT_TEST_ARTIFACT_DIR        copy summary, results, logs, probe logs, configs, and stats here
  KEEP_TEST_ARTIFACTS=1            keep tests/.tmp performance work directory
EOF
}

profile="smoke"
serving_type="all"
comparators="oxibelt,nginx,caddy"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --profile)
      profile="${2:-}"
      shift 2
      ;;
    --serving-type)
      serving_type="${2:-}"
      shift 2
      ;;
    --comparators)
      comparators="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

case "${profile}" in
  smoke|benchmark|soak) ;;
  *)
    usage
    exit 2
    ;;
esac

case "${serving_type}" in
  all|reverse-proxy|static-files|oxibelt-features|oxibelt-soak-stress|accept-multipliers) ;;
  *)
    usage
    exit 2
    ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
fixture_root="${repo_root}/tests/fixtures/oxibelt-docker-performance"
run_id="$(date +%s)-$$-${RANDOM}"
work_dir="${repo_root}/tests/.tmp/performance-${run_id}"
logs_dir="${work_dir}/logs"
probe_logs_dir="${work_dir}/probe-logs"
configs_dir="${work_dir}/configs"
tls_dir="${work_dir}/proxy-tls"
static_dir="${work_dir}/static"
results_jsonl="${work_dir}/results.jsonl"
results_json="${work_dir}/results.json"
summary_md="${work_dir}/summary.md"
stats_jsonl="${work_dir}/docker-stats.jsonl"
network_name="oxibelt-perf-${run_id}"
test_label="oxibelt.test.run=${run_id}"
perf_probe_image="oxibelt/perf-probe:${run_id}"
oxibelt_image="${OXIBELT_DOCKER_IMAGE:-oxibelt/perf-proxy:${run_id}}"
nginx_image="${OXIBELT_NGINX_IMAGE:-nginx:mainline-alpine}"
caddy_image="${OXIBELT_CADDY_IMAGE:-caddy:2-alpine}"
remove_oxibelt_image=0
active_proxy_container=""
nginx_h3_supported=0

case "${profile}" in
  smoke)
    default_duration=8
    default_warmup=2
    default_concurrency=16
    default_soak=120
    ;;
  benchmark)
    default_duration=30
    default_warmup=5
    default_concurrency=64
    default_soak=300
    ;;
  soak)
    default_duration=300
    default_warmup=10
    default_concurrency=256
    default_soak=900
    ;;
esac

duration_seconds="${OXIBELT_PERF_DURATION_SECONDS:-${default_duration}}"
warmup_seconds="${OXIBELT_PERF_WARMUP_SECONDS:-${default_warmup}}"
concurrency="${OXIBELT_PERF_CONCURRENCY:-${default_concurrency}}"
soak_seconds="${OXIBELT_PERF_SOAK_SECONDS:-${default_soak}}"
max_p99_ms="${OXIBELT_PERF_MAX_P99_MS:-10000}"
max_load_errors_per_million="${OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION:-100}"
tcp_baseline_max_p50_ms="${OXIBELT_PERF_TCP_BASELINE_MAX_P50_MS:-20}"
tcp_baseline_max_p99_ms="${OXIBELT_PERF_TCP_BASELINE_MAX_P99_MS:-35}"
static_16k_h1c_min_caddy_ratio="${OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO:-0.85}"
waf_enforcing_min_rps="${OXIBELT_PERF_WAF_ENFORCING_MIN_RPS:-11000}"
crs_enforcing_min_rps="${OXIBELT_PERF_CRS_ENFORCING_MIN_RPS:-9000}"
waf_crs_max_enforce_p99_ratio="${OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO:-1.20}"
oxibelt_baseline_scenario="${OXIBELT_PERF_OXIBELT_BASELINE_SCENARIO:-baseline}"
oxibelt_handshake_scenario="${OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO:-baseline-accept-1}"

if [[ ! "${max_load_errors_per_million}" =~ ^(0|[1-9][0-9]*)([.][0-9]+)?$ ]]; then
  echo "OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION must be a non-negative number; got '${max_load_errors_per_million}'" >&2
  exit 2
fi
if [[ ! "${static_16k_h1c_min_caddy_ratio}" =~ ^(0|[1-9][0-9]*)([.][0-9]+)?$ ]]; then
  echo "OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO must be a non-negative number; got '${static_16k_h1c_min_caddy_ratio}'" >&2
  exit 2
fi
if [[ ! "${waf_enforcing_min_rps}" =~ ^(0|[1-9][0-9]*)([.][0-9]+)?$ ]]; then
  echo "OXIBELT_PERF_WAF_ENFORCING_MIN_RPS must be a non-negative number; got '${waf_enforcing_min_rps}'" >&2
  exit 2
fi
if [[ ! "${crs_enforcing_min_rps}" =~ ^(0|[1-9][0-9]*)([.][0-9]+)?$ ]]; then
  echo "OXIBELT_PERF_CRS_ENFORCING_MIN_RPS must be a non-negative number; got '${crs_enforcing_min_rps}'" >&2
  exit 2
fi
if [[ ! "${waf_crs_max_enforce_p99_ratio}" =~ ^([1-9][0-9]*([.][0-9]+)?|0[.][0-9]*[1-9][0-9]*)$ ]]; then
  echo "OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO must be a positive number; got '${waf_crs_max_enforce_p99_ratio}'" >&2
  exit 2
fi

cleanup() {
  docker ps -aq --filter "label=${test_label}" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "${network_name}" >/dev/null 2>&1 || true
  docker rmi -f "${perf_probe_image}" >/dev/null 2>&1 || true
  if [[ "${remove_oxibelt_image}" == "1" ]]; then
    docker rmi -f "${oxibelt_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${KEEP_TEST_ARTIFACTS:-0}" != "1" ]]; then
    rm -rf "${work_dir}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "${logs_dir}" "${probe_logs_dir}" "${configs_dir}" "${tls_dir}" "${static_dir}"
: >"${results_jsonl}"
: >"${stats_jsonl}"

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_tool docker
require_tool jq
require_tool openssl

IFS=',' read -r -a comparator_list <<<"${comparators}"

has_comparator() {
  local wanted="$1"
  local item
  for item in "${comparator_list[@]}"; do
    if [[ "${item}" == "${wanted}" ]]; then
      return 0
    fi
  done
  return 1
}

generate_tls() {
  cat >"${work_dir}/downstream.cnf" <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = proxy

[req_ext]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = proxy
DNS.2 = oxibelt
DNS.3 = nginx
DNS.4 = caddy
DNS.5 = localhost
IP.1 = 127.0.0.1
EOF

  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -days 1 \
    -config "${work_dir}/downstream.cnf" \
    -keyout "${tls_dir}/privkey.pem" \
    -out "${tls_dir}/fullchain.pem" >/dev/null 2>&1
  openssl rand -base64 64 >"${tls_dir}/quic-host-key.b64"
  chmod 0644 "${tls_dir}/fullchain.pem" "${tls_dir}/privkey.pem"
  chmod 0644 "${tls_dir}/quic-host-key.b64"
}

generate_static_files() {
  openssl rand 1024 >"${static_dir}/1k.bin"
  openssl rand 16384 >"${static_dir}/16k.bin"
  openssl rand 1048576 >"${static_dir}/1m.bin"
}

copy_artifacts() {
  if [[ -n "${OXIBELT_TEST_ARTIFACT_DIR:-}" ]]; then
    mkdir -p "${OXIBELT_TEST_ARTIFACT_DIR}"
    cp -R "${work_dir}/." "${OXIBELT_TEST_ARTIFACT_DIR}/" 2>/dev/null || true
  fi
}

fail_with_diagnostics() {
  echo "$1" >&2
  collect_logs
  finalize_results || true
  copy_artifacts
  exit 1
}

collect_logs() {
  mkdir -p "${logs_dir}"
  local container
  while read -r container; do
    [[ -z "${container}" ]] && continue
    docker logs "${container}" >"${logs_dir}/${container}.log" 2>&1 || true
  done < <(docker ps -a --filter "label=${test_label}" --format '{{.Names}}')
}

sample_stats() {
  local sample="$1"
  local containers
  containers="$(docker ps -q --filter "label=${test_label}")"
  if [[ -z "${containers}" ]]; then
    return
  fi
  docker stats --no-stream --format '{{json .}}' ${containers} 2>/dev/null |
    while read -r line; do
      [[ -z "${line}" ]] && continue
      jq -c --arg sample "${sample}" '. + {sample: $sample}' <<<"${line}" >>"${stats_jsonl}" || true
    done
}

run_probe_json() {
  local probe_container="oxibelt-perf-probe-${run_id}-${RANDOM}"
  local output status json probe_label previous_arg probe_log_name probe_log_path arg
  probe_label="probe"
  previous_arg=""
  for arg in "$@"; do
    if [[ "${previous_arg}" == "--label" ]]; then
      probe_label="${arg}"
      break
    fi
    previous_arg="${arg}"
  done
  probe_log_name="${probe_label//[^A-Za-z0-9_.-]/_}"
  probe_log_path="${probe_logs_dir}/${probe_log_name}.log"
  docker create \
    --name "${probe_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    "${perf_probe_image}" \
    "$@" >/dev/null
  docker cp "${tls_dir}/fullchain.pem" "${probe_container}:/tls/proxy-ca.pem"

  status=0
  output="$(docker start -a "${probe_container}" 2>&1)" || status=$?
  {
    printf 'Command: perf-probe'
    printf ' %q' "$@"
    printf '\n\n'
    printf '%s\n' "${output}"
  } >"${probe_log_path}"
  docker rm -f "${probe_container}" >/dev/null 2>&1 || true
  if [[ "${status}" != "0" ]]; then
    echo "${output}" >&2
    return "${status}"
  fi
  json="$(printf '%s\n' "${output}" | tail -n 1)"
  if ! jq -e . >/dev/null <<<"${json}"; then
    echo "${output}" >&2
    return 1
  fi
  printf '%s\n' "${json}"
}

append_result() {
  local json="$1"
  printf '%s\n' "${json}" >>"${results_jsonl}"
  local label type protocol skipped requests rps p95 p99 errors
  label="$(jq -r '.label // "unknown"' <<<"${json}")"
  type="$(jq -r '.type // "unknown"' <<<"${json}")"
  protocol="$(jq -r '.protocol // .mode // "-"' <<<"${json}")"
  skipped="$(jq -r '.skipped // false' <<<"${json}")"
  if [[ "${skipped}" == "true" ]]; then
    printf '| `%s` | `%s` | `%s` | skipped | %s |\n' \
      "${label}" "${type}" "${protocol}" "$(jq -r '.reason // "skipped"' <<<"${json}")" >>"${summary_md}"
    return
  fi
  requests="$(jq -r '.requests // .handshakes // 0' <<<"${json}")"
  rps="$(jq -r '.rps // .handshake_per_sec // 0' <<<"${json}")"
  p95="$(jq -r '.p95_ms // 0' <<<"${json}")"
  p99="$(jq -r '.p99_ms // 0' <<<"${json}")"
  errors="$(jq -r '.errors // 0' <<<"${json}")"
  printf '| `%s` | `%s` | `%s` | %s req, %.2f/sec, p95 %.2f ms, p99 %.2f ms | errors=%s |\n' \
    "${label}" "${type}" "${protocol}" "${requests}" "${rps}" "${p95}" "${p99}" "${errors}" >>"${summary_md}"
}

assert_result() {
  local json="$1"
  local type skipped errors requests p99
  skipped="$(jq -r '.skipped // false' <<<"${json}")"
  [[ "${skipped}" == "true" ]] && return

  type="$(jq -r '.type // "unknown"' <<<"${json}")"
  errors="$(jq -r '.errors // 0' <<<"${json}")"
  requests="$(jq -r '.requests // .handshakes // 0' <<<"${json}")"
  p99="$(jq -r '.p99_ms // 0' <<<"${json}")"

  if [[ "${requests}" == "0" ]]; then
    fail_with_diagnostics "performance probe produced zero requests: $(jq -r '.label' <<<"${json}")"
  fi

  if [[ "${type}" != "stress" && "${errors}" != "0" ]]; then
    if [[ "${type}" != "load" ]] || ! load_errors_within_budget "${errors}" "${requests}"; then
      fail_with_diagnostics "performance probe reported request errors: $(jq -r '.label' <<<"${json}")"
    fi
  fi

  if [[ "${type}" == "stress" ]]; then
    local connections
    connections="$(jq -r '.connections // 0' <<<"${json}")"
    if [[ "${connections}" != "0" && "${errors}" == "${connections}" ]]; then
      fail_with_diagnostics "stress probe could not establish any useful connections: $(jq -r '.label' <<<"${json}")"
    fi
    return
  fi

  if jq -e --argjson max "${max_p99_ms}" '(.p99_ms // 0) > $max' >/dev/null <<<"${json}"; then
    fail_with_diagnostics "performance probe exceeded p99 sanity ceiling (${p99}ms > ${max_p99_ms}ms): $(jq -r '.label' <<<"${json}")"
  fi
}

assert_diagnostic_result() {
  local json="$1"
  local requests
  requests="$(jq -r '.requests // .handshakes // 0' <<<"${json}")"
  if [[ "${requests}" == "0" ]]; then
    fail_with_diagnostics "diagnostic performance probe produced zero requests: $(jq -r '.label' <<<"${json}")"
  fi
}

load_errors_within_budget() {
  local errors="$1"
  local requests="$2"
  jq -n -e \
    --argjson errors "${errors}" \
    --argjson requests "${requests}" \
    --argjson max "${max_load_errors_per_million}" \
    '($requests > 0) and (($errors * 1000000 / $requests) <= $max)' >/dev/null
}

assert_oxibelt_tcp_baseline() {
  local label json p50 p99
  for label in oxibelt-h1-keepalive oxibelt-h2; do
    json="$(jq -c --arg label "${label}" 'select(.label == $label and ((.skipped // false) | not))' "${results_jsonl}" | tail -n 1)"
    if [[ -z "${json}" ]]; then
      fail_with_diagnostics "missing OxiBelt TCP baseline result: ${label}"
    fi
    p50="$(jq -r '.p50_ms // 0' <<<"${json}")"
    p99="$(jq -r '.p99_ms // 0' <<<"${json}")"
    if jq -e --argjson max "${tcp_baseline_max_p50_ms}" '(.p50_ms // 0) > $max' >/dev/null <<<"${json}"; then
      fail_with_diagnostics "OxiBelt TCP baseline p50 exceeded latency-floor gate (${p50}ms > ${tcp_baseline_max_p50_ms}ms): ${label}"
    fi
    if jq -e --argjson max "${tcp_baseline_max_p99_ms}" '(.p99_ms // 0) > $max' >/dev/null <<<"${json}"; then
      fail_with_diagnostics "OxiBelt TCP baseline p99 exceeded latency-floor gate (${p99}ms > ${tcp_baseline_max_p99_ms}ms): ${label}"
    fi
  done
}

assert_static_16k_h1c_caddy_ratio() {
  local oxibelt_json caddy_json oxibelt_rps caddy_rps ratio
  oxibelt_json="$(jq -c 'select(.label == "oxibelt-static-16k-h1c" and ((.skipped // false) | not))' "${results_jsonl}" | tail -n 1)"
  caddy_json="$(jq -c 'select(.label == "caddy-static-16k-h1c" and ((.skipped // false) | not))' "${results_jsonl}" | tail -n 1)"
  if [[ -z "${oxibelt_json}" || -z "${caddy_json}" ]]; then
    return
  fi

  oxibelt_rps="$(jq -r '.rps // 0' <<<"${oxibelt_json}")"
  caddy_rps="$(jq -r '.rps // 0' <<<"${caddy_json}")"
  if jq -n -e --argjson caddy "${caddy_rps}" '$caddy <= 0' >/dev/null; then
    fail_with_diagnostics "Caddy static-16k-h1c RPS is not positive; cannot evaluate static regression gate"
  fi
  ratio="$(jq -n -r --argjson oxibelt "${oxibelt_rps}" --argjson caddy "${caddy_rps}" '$oxibelt / $caddy')"
  if jq -n -e --argjson ratio "${ratio}" --argjson min "${static_16k_h1c_min_caddy_ratio}" '$ratio < $min' >/dev/null; then
    fail_with_diagnostics "OxiBelt static-16k-h1c regression gate failed: ratio ${ratio} < ${static_16k_h1c_min_caddy_ratio} vs Caddy (${oxibelt_rps} RPS vs ${caddy_rps} RPS)"
  fi
}

assert_waf_crs_regression_gates() {
  local waf_monitor_json waf_enforcing_json crs_monitor_json crs_enforcing_json
  local waf_enforcing_rps crs_enforcing_rps
  local waf_monitor_p99 waf_enforcing_p99 crs_monitor_p99 crs_enforcing_p99
  local waf_p99_ratio crs_p99_ratio

  waf_monitor_json="$(jq -c 'select(.label == "oxibelt-waf-monitor" and ((.skipped // false) | not))' "${results_jsonl}" | tail -n 1)"
  waf_enforcing_json="$(jq -c 'select(.label == "oxibelt-waf-enforcing" and ((.skipped // false) | not))' "${results_jsonl}" | tail -n 1)"
  crs_monitor_json="$(jq -c 'select(.label == "oxibelt-crs-monitor" and ((.skipped // false) | not))' "${results_jsonl}" | tail -n 1)"
  crs_enforcing_json="$(jq -c 'select(.label == "oxibelt-crs-enforcing" and ((.skipped // false) | not))' "${results_jsonl}" | tail -n 1)"

  if [[ -z "${waf_monitor_json}" ]]; then
    fail_with_diagnostics "missing OxiBelt WAF/CRS performance result: oxibelt-waf-monitor"
  fi
  if [[ -z "${waf_enforcing_json}" ]]; then
    fail_with_diagnostics "missing OxiBelt WAF/CRS performance result: oxibelt-waf-enforcing"
  fi
  if [[ -z "${crs_monitor_json}" ]]; then
    fail_with_diagnostics "missing OxiBelt WAF/CRS performance result: oxibelt-crs-monitor"
  fi
  if [[ -z "${crs_enforcing_json}" ]]; then
    fail_with_diagnostics "missing OxiBelt WAF/CRS performance result: oxibelt-crs-enforcing"
  fi

  waf_enforcing_rps="$(jq -r '.rps // 0' <<<"${waf_enforcing_json}")"
  crs_enforcing_rps="$(jq -r '.rps // 0' <<<"${crs_enforcing_json}")"
  if jq -n -e --argjson rps "${waf_enforcing_rps}" --argjson min "${waf_enforcing_min_rps}" '$rps < $min' >/dev/null; then
    fail_with_diagnostics "OxiBelt WAF enforcing regression gate failed: RPS ${waf_enforcing_rps} < ${waf_enforcing_min_rps}"
  fi
  if jq -n -e --argjson rps "${crs_enforcing_rps}" --argjson min "${crs_enforcing_min_rps}" '$rps < $min' >/dev/null; then
    fail_with_diagnostics "OxiBelt CRS enforcing regression gate failed: RPS ${crs_enforcing_rps} < ${crs_enforcing_min_rps}"
  fi

  waf_monitor_p99="$(jq -r '.p99_ms // 0' <<<"${waf_monitor_json}")"
  waf_enforcing_p99="$(jq -r '.p99_ms // 0' <<<"${waf_enforcing_json}")"
  crs_monitor_p99="$(jq -r '.p99_ms // 0' <<<"${crs_monitor_json}")"
  crs_enforcing_p99="$(jq -r '.p99_ms // 0' <<<"${crs_enforcing_json}")"
  if jq -n -e --argjson p99 "${waf_monitor_p99}" '$p99 <= 0' >/dev/null; then
    fail_with_diagnostics "OxiBelt WAF monitor p99 is not positive; cannot evaluate WAF/CRS p99 regression gate"
  fi
  if jq -n -e --argjson p99 "${waf_enforcing_p99}" '$p99 <= 0' >/dev/null; then
    fail_with_diagnostics "OxiBelt WAF enforcing p99 is not positive; cannot evaluate WAF/CRS p99 regression gate"
  fi
  if jq -n -e --argjson p99 "${crs_monitor_p99}" '$p99 <= 0' >/dev/null; then
    fail_with_diagnostics "OxiBelt CRS monitor p99 is not positive; cannot evaluate WAF/CRS p99 regression gate"
  fi
  if jq -n -e --argjson p99 "${crs_enforcing_p99}" '$p99 <= 0' >/dev/null; then
    fail_with_diagnostics "OxiBelt CRS enforcing p99 is not positive; cannot evaluate WAF/CRS p99 regression gate"
  fi

  waf_p99_ratio="$(jq -n -r --argjson enforcing "${waf_enforcing_p99}" --argjson monitor "${waf_monitor_p99}" '$enforcing / $monitor')"
  crs_p99_ratio="$(jq -n -r --argjson enforcing "${crs_enforcing_p99}" --argjson monitor "${crs_monitor_p99}" '$enforcing / $monitor')"
  if jq -n -e --argjson ratio "${waf_p99_ratio}" --argjson max "${waf_crs_max_enforce_p99_ratio}" '$ratio > $max' >/dev/null; then
    fail_with_diagnostics "OxiBelt WAF p99 regression gate failed: enforcing/monitor ratio ${waf_p99_ratio} > ${waf_crs_max_enforce_p99_ratio} (${waf_enforcing_p99}ms vs ${waf_monitor_p99}ms)"
  fi
  if jq -n -e --argjson ratio "${crs_p99_ratio}" --argjson max "${waf_crs_max_enforce_p99_ratio}" '$ratio > $max' >/dev/null; then
    fail_with_diagnostics "OxiBelt CRS p99 regression gate failed: enforcing/monitor ratio ${crs_p99_ratio} > ${waf_crs_max_enforce_p99_ratio} (${crs_enforcing_p99}ms vs ${crs_monitor_p99}ms)"
  fi
}

record_skip() {
  local label="$1"
  local type="$2"
  local protocol="$3"
  local reason="$4"
  local json
  json="$(jq -cn \
    --arg label "${label}" \
    --arg type "${type}" \
    --arg protocol "${protocol}" \
    --arg reason "${reason}" \
    '{label: $label, type: $type, protocol: $protocol, skipped: true, reason: $reason}')"
  append_result "${json}"
}

run_load() {
  local label="$1"
  local protocol="$2"
  local host="$3"
  local path="$4"
  local duration="$5"
  local conc="$6"
  local port="8443"
  local json
  if [[ "${protocol}" == "h1c" ]]; then
    port="8080"
  fi
  json="$(run_probe_json load \
    --label "${label}" \
    --protocol "${protocol}" \
    --host "${host}" \
    --port "${port}" \
    --server-name proxy \
    --authority example.test \
    --path "${path}" \
    --ca-cert /tls/proxy-ca.pem \
    --duration-seconds "${duration}" \
    --warmup-seconds "${warmup_seconds}" \
    --concurrency "${conc}" \
    --expect-status 200)"
  append_result "${json}"
  assert_result "${json}"
  sample_stats "${label}"
}

run_static_h3_load() {
  local comparator="$1"
  local host="$2"
  local h3_mode="$3"
  local size="$4"
  local path="$5"
  case "${h3_mode}" in
    required)
      if h3_probe_succeeds "${host}"; then
        run_load "${comparator}-static-${size}-h3" h3 "${host}" "${path}" "${duration_seconds}" "${concurrency}"
      else
        fail_with_diagnostics "mandatory HTTP/3 probe failed for ${comparator} static files: functional QUIC probe did not complete"
      fi
      ;;
    optional)
      if h3_probe_succeeds "${host}"; then
        run_load "${comparator}-static-${size}-h3" h3 "${host}" "${path}" "${duration_seconds}" "${concurrency}"
      else
        record_skip "${comparator}-static-${size}-h3" load h3 "optional HTTP/3 support was detected, but a functional QUIC probe did not complete"
      fi
      ;;
    disabled)
      record_skip "${comparator}-static-${size}-h3" load h3 "HTTP/3 is not available for this comparator image"
      ;;
    *)
      fail_with_diagnostics "invalid HTTP/3 performance mode for ${comparator} static files: ${h3_mode}"
      ;;
  esac
}

run_static_loads() {
  local comparator="$1"
  local host="$2"
  local h3_mode="$3"
  if [[ "${profile}" == "smoke" ]]; then
    run_load "${comparator}-static-16k-h1c" h1c "${host}" "/static/16k.bin" "${duration_seconds}" "${concurrency}"
    return
  fi
  if [[ "${profile}" != "benchmark" ]]; then
    return
  fi
  local size path
  for size in 1k 16k 1m; do
    path="/static/${size}.bin"
    run_load "${comparator}-static-${size}-h1c" h1c "${host}" "${path}" "${duration_seconds}" "${concurrency}"
    run_load "${comparator}-static-${size}-h1" h1 "${host}" "${path}" "${duration_seconds}" "${concurrency}"
    run_load "${comparator}-static-${size}-h2" h2 "${host}" "${path}" "${duration_seconds}" "${concurrency}"
    run_static_h3_load "${comparator}" "${host}" "${h3_mode}" "${size}" "${path}"
  done
}

run_handshake() {
  run_handshake_with_options "$1" "$2" "$3" fresh 0 strict none
}

run_handshake_resumption_diagnostic() {
  run_handshake_with_options "$1" "$2" "$3" worker 25 diagnostic none
}

run_handshake_with_storage_diagnostics() {
  run_handshake_with_options "$1" "$2" "$3" fresh 0 strict tls-storage
}

run_handshake_with_options() {
  local label="$1"
  local protocol="$2"
  local host="$3"
  local client_resumption="$4"
  local post_handshake_observe_ms="$5"
  local result_mode="$6"
  local diagnostics="$7"
  local before_metrics after_metrics storage_delta json
  if [[ "${diagnostics}" == "tls-storage" ]]; then
    before_metrics="$(server_session_storage_metrics "${host}" "${label}-metrics-before")"
  fi
  json="$(run_probe_json handshake \
    --label "${label}" \
    --protocol "${protocol}" \
    --host "${host}" \
    --port 8443 \
    --server-name proxy \
    --ca-cert /tls/proxy-ca.pem \
    --duration-seconds "${duration_seconds}" \
    --concurrency "${concurrency}" \
    --client-resumption "${client_resumption}" \
    --post-handshake-observe-ms "${post_handshake_observe_ms}")"
  if [[ "${diagnostics}" == "tls-storage" ]]; then
    after_metrics="$(server_session_storage_metrics "${host}" "${label}-metrics-after")"
    storage_delta="$(server_session_storage_delta "${before_metrics}" "${after_metrics}")"
    json="$(jq -c --argjson storage "${storage_delta}" '. + {server_session_storage: $storage}' <<<"${json}")"
  fi
  append_result "${json}"
  if [[ "${result_mode}" == "strict" ]]; then
    assert_result "${json}"
  else
    assert_diagnostic_result "${json}"
  fi
  sample_stats "${label}"
}

server_session_storage_metrics() {
  local host="$1"
  local label="$2"
  local attempt json
  for attempt in $(seq 1 10); do
    if json="$(run_probe_json metrics \
      --label "${label}-${attempt}" \
      --host "${host}" \
      --port 9090 \
      --authority ops.test \
      --path /metrics)"; then
      jq -c '.server_session_storage // {
        put_count: 0,
        get_count: 0,
        take_count: 0,
        lock_wait_ns: 0,
        put_duration_ns: 0
      }' <<<"${json}"
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "metrics endpoint did not become ready for ${label}"
}

server_session_storage_delta() {
  local before="$1"
  local after="$2"
  jq -n -c \
    --argjson before "${before}" \
    --argjson after "${after}" \
    'def diff($name):
       (($after[$name] // 0) - ($before[$name] // 0)) as $value
       | if $value < 0 then 0 else $value end;
     {
       put_count: diff("put_count"),
       get_count: diff("get_count"),
       take_count: diff("take_count"),
       lock_wait_ns: diff("lock_wait_ns"),
       put_duration_ns: diff("put_duration_ns")
     }'
}

run_stress() {
  local label="$1"
  local mode="$2"
  local connections="$3"
  local duration="$4"
  local bytes="$5"
  local json
  json="$(run_probe_json stress \
    --label "${label}" \
    --mode "${mode}" \
    --host oxibelt \
    --port 8080 \
    --authority example.test \
    --connections "${connections}" \
    --duration-seconds "${duration}" \
    --bytes "${bytes}")"
  append_result "${json}"
  assert_result "${json}"
  sample_stats "${label}"
}

h3_probe_succeeds() {
  local host="$1"
  local json
  if ! json="$(run_probe_json load \
    --label "h3-ready-${host}" \
    --protocol h3 \
    --host "${host}" \
    --port 8443 \
    --server-name proxy \
    --authority example.test \
    --path "/ready?body=ok" \
    --ca-cert /tls/proxy-ca.pem \
    --duration-seconds 1 \
    --warmup-seconds 0 \
    --concurrency 1 \
    --expect-status 200)"; then
    return 1
  fi
  jq -e '(.requests // 0) > 0 and (.errors // 0) == 0 and ((.statuses["200"] // 0) > 0)' >/dev/null <<<"${json}"
}

wait_for_tls_proxy() {
  local host="$1"
  local attempt
  for attempt in $(seq 1 30); do
    if run_probe_json load \
      --label "ready-${host}" \
      --protocol h1 \
      --host "${host}" \
      --port 8443 \
      --server-name proxy \
      --authority example.test \
      --path "/ready?body=ok" \
      --ca-cert /tls/proxy-ca.pem \
      --duration-seconds 1 \
      --warmup-seconds 0 \
      --concurrency 1 \
      --expect-status 200 >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

stop_active_proxy() {
  if [[ -n "${active_proxy_container}" ]]; then
    docker logs "${active_proxy_container}" >"${logs_dir}/${active_proxy_container}.log" 2>&1 || true
    docker rm -f "${active_proxy_container}" >/dev/null 2>&1 || true
    active_proxy_container=""
  fi
}

start_oxibelt() {
  local scenario="$1"
  local alias_name="$2"
  local fixture_dir="${fixture_root}/oxibelt/${scenario}"
  local container="oxibelt-perf-${scenario}-${run_id}"
  stop_active_proxy
  if [[ ! -d "${fixture_dir}/config" ]]; then
    fail_with_diagnostics "missing OxiBelt performance fixture: ${scenario}"
  fi
  mkdir -p "${configs_dir}/oxibelt-${scenario}"
  cp -R "${fixture_dir}/." "${configs_dir}/oxibelt-${scenario}/"
  cp -R "${tls_dir}" "${configs_dir}/oxibelt-${scenario}/cert"

  docker create \
    --name "${container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias "${alias_name}" \
    -e OXIBELT_INSTANCE_ID="perf-${scenario}" \
    "${oxibelt_image}" >/dev/null
  docker cp "${fixture_dir}/config/." "${container}:/etc/oxibelt/config"
  docker cp "${tls_dir}/." "${container}:/etc/oxibelt/cert"
  docker cp "${static_dir}/." "${container}:/etc/oxibelt/static"
  if [[ -d "${fixture_dir}/oxirule" ]]; then
    docker cp "${fixture_dir}/oxirule/." "${container}:/etc/oxibelt/oxirule"
  fi
  docker start "${container}" >/dev/null
  active_proxy_container="${container}"
  if ! wait_for_tls_proxy "${alias_name}"; then
    fail_with_diagnostics "OxiBelt performance proxy did not become ready for ${scenario}"
  fi
}

start_nginx() {
  local container="nginx-perf-${run_id}"
  local config="nginx.conf"
  stop_active_proxy
  if [[ "${nginx_h3_supported}" == "1" ]]; then
    config="nginx-h3.conf"
  fi
  mkdir -p "${configs_dir}/nginx"
  cp "${fixture_root}/nginx/${config}" "${configs_dir}/nginx/nginx.conf"
  cp -R "${tls_dir}" "${configs_dir}/nginx/cert"

  docker create \
    --name "${container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias nginx \
    "${nginx_image}" >/dev/null
  docker cp "${fixture_root}/nginx/${config}" "${container}:/etc/nginx/nginx.conf"
  docker cp "${tls_dir}/fullchain.pem" "${container}:/etc/nginx/fullchain.pem"
  docker cp "${tls_dir}/privkey.pem" "${container}:/etc/nginx/privkey.pem"
  docker cp "${static_dir}/." "${container}:/srv/static"
  docker start "${container}" >/dev/null
  active_proxy_container="${container}"
  if ! wait_for_tls_proxy nginx; then
    fail_with_diagnostics "nginx performance proxy did not become ready"
  fi
}

start_caddy() {
  local container="caddy-perf-${run_id}"
  stop_active_proxy
  mkdir -p "${configs_dir}/caddy"
  cp "${fixture_root}/caddy/Caddyfile" "${configs_dir}/caddy/Caddyfile"
  cp -R "${tls_dir}" "${configs_dir}/caddy/cert"

  docker create \
    --name "${container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias caddy \
    "${caddy_image}" >/dev/null
  docker cp "${fixture_root}/caddy/Caddyfile" "${container}:/etc/caddy/Caddyfile"
  docker cp "${tls_dir}/fullchain.pem" "${container}:/etc/caddy/fullchain.pem"
  docker cp "${tls_dir}/privkey.pem" "${container}:/etc/caddy/privkey.pem"
  docker cp "${static_dir}/." "${container}:/srv/static"
  docker start "${container}" >/dev/null
  active_proxy_container="${container}"
  if ! wait_for_tls_proxy caddy; then
    fail_with_diagnostics "Caddy performance proxy did not become ready"
  fi
}

detect_nginx_h3() {
  if docker run --rm "${nginx_image}" nginx -V 2>&1 | grep -F -- '--with-http_v3_module' >/dev/null; then
    nginx_h3_supported=1
  else
    nginx_h3_supported=0
  fi
}

run_common_loads() {
  local comparator="$1"
  local host="$2"
  local h3_mode="$3"
  run_load "${comparator}-h1-keepalive" h1 "${host}" "/perf/h1?body=ok" "${duration_seconds}" "${concurrency}"
  run_load "${comparator}-h2" h2 "${host}" "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"
  case "${h3_mode}" in
    required)
      if h3_probe_succeeds "${host}"; then
        run_load "${comparator}-h3" h3 "${host}" "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
      else
        fail_with_diagnostics "mandatory HTTP/3 probe failed for ${comparator}: functional QUIC probe did not complete"
      fi
      ;;
    optional)
      if h3_probe_succeeds "${host}"; then
        run_load "${comparator}-h3" h3 "${host}" "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
      else
        record_skip "${comparator}-h3" load h3 "optional HTTP/3 support was detected, but a functional QUIC probe did not complete"
      fi
      ;;
    disabled)
      record_skip "${comparator}-h3" load h3 "HTTP/3 is not available for this comparator image"
      ;;
    *)
      fail_with_diagnostics "invalid HTTP/3 performance mode for ${comparator}: ${h3_mode}"
      ;;
  esac
}

run_accept_multiplier_common_loads() {
  local label_prefix="$1"
  run_load "${label_prefix}-h1-keepalive" h1 oxibelt "/perf/h1?body=ok" "${duration_seconds}" "${concurrency}"
  run_load "${label_prefix}-h2" h2 oxibelt "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"
  if h3_probe_succeeds oxibelt; then
    run_load "${label_prefix}-h3" h3 oxibelt "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
  else
    fail_with_diagnostics "mandatory HTTP/3 probe failed for ${label_prefix}: functional QUIC probe did not complete"
  fi
}

run_accept_multiplier_profile() {
  local suffix="$1"
  local baseline_scenario="$2"
  local waf_scenario="$3"
  local crs_scenario="$4"
  local label_prefix="oxibelt-${suffix}"

  start_oxibelt "${baseline_scenario}" oxibelt
  run_accept_multiplier_common_loads "${label_prefix}"
  run_load "${label_prefix}-static-16k-h1c" h1c oxibelt "/static/16k.bin" "${duration_seconds}" "${concurrency}"
  run_handshake "${label_prefix}-tls-handshake-h2" h2 oxibelt

  start_oxibelt "${waf_scenario}" oxibelt
  run_load "${label_prefix}-waf-enforcing" h2 oxibelt "/perf/waf?body=ok" "${duration_seconds}" "${concurrency}"

  start_oxibelt "${crs_scenario}" oxibelt
  run_load "${label_prefix}-crs-enforcing" h2 oxibelt "/perf/crs?body=ok" "${duration_seconds}" "${concurrency}"
}

run_oxibelt_tls_resumption_handshake_rows() {
  start_oxibelt tls-resumption-off oxibelt
  run_handshake_with_storage_diagnostics "oxibelt-tls-handshake-h2-resumption-off" h2 oxibelt

  start_oxibelt tls-resumption-stateless-tickets-2 oxibelt
  run_handshake_with_storage_diagnostics "oxibelt-tls-handshake-h2-resumption-stateless-tickets-2" h2 oxibelt

  start_oxibelt tls-resumption-stateful-tickets-1 oxibelt
  run_handshake_with_storage_diagnostics "oxibelt-tls-handshake-h2-resumption-stateful-tickets-1" h2 oxibelt

  start_oxibelt tls-resumption-stateful-tickets-2 oxibelt
  run_handshake_with_storage_diagnostics "oxibelt-tls-handshake-h2-resumption-stateful-tickets-2" h2 oxibelt
}

run_oxibelt_specific_benchmarks() {
  start_oxibelt waf-monitor oxibelt
  run_load "oxibelt-waf-monitor" h2 oxibelt "/perf/waf?body=ok" "${duration_seconds}" "${concurrency}"

  start_oxibelt waf-enforcing oxibelt
  run_load "oxibelt-waf-enforcing" h2 oxibelt "/perf/waf?body=ok" "${duration_seconds}" "${concurrency}"

  start_oxibelt crs-monitor oxibelt
  run_load "oxibelt-crs-monitor" h2 oxibelt "/perf/crs?body=ok" "${duration_seconds}" "${concurrency}"

  start_oxibelt crs-enforcing oxibelt
  run_load "oxibelt-crs-enforcing" h2 oxibelt "/perf/crs?body=ok" "${duration_seconds}" "${concurrency}"

  assert_waf_crs_regression_gates

  start_oxibelt cache oxibelt
  run_load "oxibelt-cache-miss" h2 oxibelt "/perf/cache-miss?body_repeat=4096&cache_control=no-store" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-cache-hit" h2 oxibelt "/perf/cache-hit?body_repeat=4096&cache_control=public" "${duration_seconds}" "${concurrency}"
  sleep 2
  run_load "oxibelt-cache-revalidate" h2 oxibelt "/perf/cache-revalidate?body_repeat=4096&cache_control=public-max-age-1&etag=perf" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-cache-stale" h2 oxibelt "/perf/cache-stale?body_repeat=4096&cache_control=public-stale-revalidate" "${duration_seconds}" "${concurrency}"
}

run_oxibelt_soak_and_stress() {
  start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
  run_load "oxibelt-soak-h1" h1 oxibelt "/perf/soak?body=ok" "${soak_seconds}" "${concurrency}"
  run_stress "oxibelt-slowloris" slowloris 32 5 1024
  run_stress "oxibelt-large-header" large-header 8 1 65536
  run_stress "oxibelt-large-body" large-body 8 1 1048576
  run_stress "oxibelt-idle" idle 32 5 1024
  run_stress "oxibelt-half-closed" half-close 8 1 1024
}

run_manual_soak_presets() {
  local presets="${OXIBELT_PERF_SOAK_CONCURRENCY_PRESETS:-10000,50000,100000}"
  local fd_limit
  fd_limit="$(ulimit -n || echo 1024)"
  IFS=',' read -r -a preset_values <<<"${presets}"
  start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
  local preset
  for preset in "${preset_values[@]}"; do
    if ! [[ "${preset}" =~ ^[0-9]+$ ]]; then
      record_skip "oxibelt-soak-${preset}" load h1 "invalid concurrency preset"
      continue
    fi
    if (( preset * 2 > fd_limit )); then
      record_skip "oxibelt-soak-${preset}" load h1 "host fd limit ${fd_limit} is too low for ${preset} connections"
      continue
    fi
    run_load "oxibelt-soak-${preset}" h1 oxibelt "/perf/soak?body=ok" "${soak_seconds}" "${preset}"
  done
}

run_reverse_proxy_group() {
  if has_comparator oxibelt; then
    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
    run_common_loads oxibelt oxibelt required
    assert_oxibelt_tcp_baseline
    start_oxibelt "${oxibelt_handshake_scenario}" oxibelt
    run_handshake "oxibelt-tls-handshake-h2" h2 oxibelt
    run_handshake_resumption_diagnostic "oxibelt-tls-handshake-h2-resumption-diagnostic" h2 oxibelt
    run_oxibelt_tls_resumption_handshake_rows
  fi

  if has_comparator nginx; then
    start_nginx
    nginx_h3_mode=disabled
    if [[ "${nginx_h3_supported}" == "1" ]]; then
      nginx_h3_mode=optional
    fi
    run_common_loads nginx nginx "${nginx_h3_mode}"
  fi

  if has_comparator caddy; then
    start_caddy
    run_common_loads caddy caddy required
  fi
}

run_static_files_group() {
  if has_comparator oxibelt; then
    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
    run_static_loads oxibelt oxibelt required
  fi

  if has_comparator nginx; then
    start_nginx
    nginx_h3_mode=disabled
    if [[ "${nginx_h3_supported}" == "1" ]]; then
      nginx_h3_mode=optional
    fi
    run_static_loads nginx nginx "${nginx_h3_mode}"
  fi

  if has_comparator caddy; then
    start_caddy
    run_static_loads caddy caddy required
  fi

  assert_static_16k_h1c_caddy_ratio
}

run_oxibelt_features_group() {
  if has_comparator oxibelt; then
    run_oxibelt_specific_benchmarks
  fi
}

run_oxibelt_soak_stress_group() {
  if ! has_comparator oxibelt; then
    return
  fi

  if [[ "${profile}" == "smoke" ]]; then
    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
    run_load "oxibelt-smoke-soak" h1 oxibelt "/perf/smoke-soak?body=ok" "${soak_seconds}" "${concurrency}"
  elif [[ "${profile}" == "benchmark" ]]; then
    run_oxibelt_soak_and_stress
  elif [[ "${profile}" == "soak" ]]; then
    run_manual_soak_presets
    run_oxibelt_soak_and_stress
  fi
}

run_accept_multipliers_group() {
  if ! has_comparator oxibelt; then
    return
  fi

  run_accept_multiplier_profile accept-0_5 baseline waf-enforcing crs-enforcing
  run_accept_multiplier_profile accept-1_0 baseline-accept-1 waf-enforcing-accept-1 crs-enforcing-accept-1
}

run_all_serving_types() {
  if has_comparator oxibelt; then
    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
    run_common_loads oxibelt oxibelt required
    run_static_loads oxibelt oxibelt required
    assert_oxibelt_tcp_baseline
    start_oxibelt "${oxibelt_handshake_scenario}" oxibelt
    run_handshake "oxibelt-tls-handshake-h2" h2 oxibelt
    run_handshake_resumption_diagnostic "oxibelt-tls-handshake-h2-resumption-diagnostic" h2 oxibelt
    run_oxibelt_tls_resumption_handshake_rows
    if [[ "${profile}" == "smoke" ]]; then
      run_load "oxibelt-smoke-soak" h1 oxibelt "/perf/smoke-soak?body=ok" "${soak_seconds}" "${concurrency}"
    fi
  fi

  if has_comparator nginx; then
    start_nginx
    nginx_h3_mode=disabled
    if [[ "${nginx_h3_supported}" == "1" ]]; then
      nginx_h3_mode=optional
    fi
    run_common_loads nginx nginx "${nginx_h3_mode}"
    run_static_loads nginx nginx "${nginx_h3_mode}"
  fi

  if has_comparator caddy; then
    start_caddy
    run_common_loads caddy caddy required
    run_static_loads caddy caddy required
  fi

  assert_static_16k_h1c_caddy_ratio

  if has_comparator oxibelt && [[ "${profile}" == "benchmark" || "${profile}" == "soak" ]]; then
    run_oxibelt_specific_benchmarks
  fi

  if has_comparator oxibelt && [[ "${profile}" == "benchmark" ]]; then
    run_oxibelt_soak_and_stress
  elif has_comparator oxibelt && [[ "${profile}" == "soak" ]]; then
    run_manual_soak_presets
    run_oxibelt_soak_and_stress
  fi
}

finalize_results() {
  if [[ -s "${results_jsonl}" ]]; then
    jq -s '.' "${results_jsonl}" >"${results_json}"
  else
    printf '[]\n' >"${results_json}"
  fi
  {
    echo
    echo "Artifacts:"
    echo
    echo "- results.json"
    echo "- docker-stats.jsonl"
    echo "- logs/"
    echo "- probe-logs/"
    echo "- configs/"
  } >>"${summary_md}"
}

generate_tls
generate_static_files

cat >"${summary_md}" <<EOF
# OxiBelt Docker Performance (${profile})

- Run id: \`${run_id}\`
- Serving type: \`${serving_type}\`
- Comparators: \`${comparators}\`
- OxiBelt baseline fixture: \`${oxibelt_baseline_scenario}\`
- OxiBelt handshake fixture: \`${oxibelt_handshake_scenario}\`
- Duration: \`${duration_seconds}s\`
- Warmup: \`${warmup_seconds}s\`
- Concurrency: \`${concurrency}\`

| Scenario | Type | Protocol | Result | Notes |
| --- | --- | --- | --- | --- |
EOF

docker network create "${network_name}" >/dev/null

docker build \
  -t "${perf_probe_image}" \
  -f "${repo_root}/tests/docker/perf_probe/Dockerfile" \
  "${repo_root}/tests/docker/perf_probe" >/dev/null

if has_comparator oxibelt && [[ -z "${OXIBELT_DOCKER_IMAGE:-}" ]]; then
  remove_oxibelt_image=1
  docker build \
    -t "${oxibelt_image}" \
    -f "${repo_root}/source/ops/Dockerfile.alpine" \
    "${repo_root}" >/dev/null
fi

if has_comparator nginx; then
  detect_nginx_h3
fi

docker run -d \
  --name "perf-upstream-${run_id}" \
  --label "${test_label}" \
  --network "${network_name}" \
  --network-alias perf-upstream \
  "${perf_probe_image}" \
  upstream \
  --listen 0.0.0.0:18080 \
  --name perf-upstream >/dev/null

sleep 1

case "${serving_type}" in
  all)
    run_all_serving_types
    ;;
  reverse-proxy)
    run_reverse_proxy_group
    ;;
  static-files)
    run_static_files_group
    ;;
  oxibelt-features)
    run_oxibelt_features_group
    ;;
  oxibelt-soak-stress)
    run_oxibelt_soak_stress_group
    ;;
  accept-multipliers)
    run_accept_multipliers_group
    ;;
esac

stop_active_proxy
collect_logs
finalize_results
copy_artifacts

echo "Docker performance profile ${profile} serving type ${serving_type} completed"
echo "Summary: ${summary_md}"
