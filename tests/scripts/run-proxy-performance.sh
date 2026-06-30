#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tests/scripts/run-proxy-performance.sh --profile smoke|benchmark|soak [--serving-type all|reverse-proxy|static-files|oxibelt-features|oxibelt-soak-stress|accept-multipliers|remote-signer|pool-concurrency|runtime-direct-h1|metrics-mode|oxibelt-aggressive-long-run] [--comparators oxibelt,nginx,caddy,openresty]

Environment:
  OXIBELT_DOCKER_IMAGE             OxiBelt image to test; built locally when unset
  OXIBELT_DOCKER_COMMAND           Docker CLI command to invoke (default: docker)
  OXIBELT_AMD64_TARGET_CPU         AMD64 target CPU label recorded in result rows
  OXIBELT_NGINX_IMAGE              nginx comparator image (default: nginx:mainline-alpine)
  OXIBELT_NGINX_H3_MODE            auto, required, optional, or disabled (default: auto)
  OXIBELT_CADDY_IMAGE              Caddy comparator image (default: caddy:2-alpine)
  OXIBELT_OPENRESTY_IMAGE          OpenResty comparator image (default: openresty/openresty:1.31.1.1-1-alpine)
  OXIBELT_PERF_PROBE_IMAGE         prebuilt perf-probe image to reuse; built locally when unset
  OXIBELT_EXTERNAL_BENCHMARKS      run h2load/oha/wrk validation rows, 1 or 0 (default: 1)
  OXIBELT_EXTERNAL_BENCHMARK_TOOLS comma-separated h2load,oha,wrk subset (default: h2load,oha,wrk)
  OXIBELT_EXTERNAL_BENCHMARK_IMAGE prebuilt external benchmark image to reuse; built locally when unset
  OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE
                                      fail or warn for external benchmark failures (default: warn)
  OXIBELT_EXTERNAL_OHA_QPS         fixed oha request rate for SLO validation (default: 1000)
  OXIBELT_EXTERNAL_OHA_MAX_P99_MS  max oha p99 latency in milliseconds (default: 250)
  OXIBELT_EXTERNAL_OHA_MAX_ERROR_RATE
                                      max oha error rate from 0.0 to 1.0 (default: 0)
  OXIBELT_PERF_DURATION_SECONDS    load duration override
  OXIBELT_PERF_WARMUP_SECONDS      warmup duration override
  OXIBELT_PERF_CONCURRENCY         load concurrency override
  OXIBELT_PERF_SOAK_SECONDS        soak duration override
  OXIBELT_PERF_AGGRESSIVE_STRESS_SECONDS
                                      fixed aggressive stress phase duration (default: 180)
  OXIBELT_PERF_RESOURCE_MAX_MEMORY_DELTA_BYTES
                                      max OxiBelt RSS drift during aggressive long-run (default: 268435456)
  OXIBELT_PERF_RESOURCE_MAX_FD_DELTA
                                      max OxiBelt FD drift during aggressive long-run (default: 256)
  OXIBELT_PERF_RESOURCE_MAX_TASK_DELTA
                                      max OxiBelt task/thread drift during aggressive long-run (default: 64)
  OXIBELT_PERF_RESOURCE_SETTLE_SECONDS
                                      seconds to wait before the final aggressive resource snapshot (default: 30)
  OXIBELT_PERF_MAX_P99_MS          sanity ceiling for load p99 latency
  OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION
                                      load request error budget per million completed requests
  OXIBELT_PERF_TCP_BASELINE_MAX_P50_MS
                                      OxiBelt H1/H2 baseline p50 latency ceiling
  OXIBELT_PERF_TCP_BASELINE_MAX_P99_MS
                                      OxiBelt H1/H2 baseline p99 latency ceiling
  OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO
                                      minimum OxiBelt/Caddy RPS ratio for static 16KiB H1C (default: 0.80)
  OXIBELT_PERF_H1_FAST_PATH_MIN_HIT_RATE
                                      minimum OxiBelt H1 plain-proxy fast-path hit rate (default: 0.99)
  OXIBELT_PERF_WAF_ENFORCING_MIN_RPS
                                      minimum OxiBelt WAF enforcing RPS (default: 10000)
  OXIBELT_PERF_CRS_ENFORCING_MIN_RPS
                                      minimum OxiBelt CRS enforcing RPS (default: 8000)
  OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO
                                      maximum enforcing/monitor p99 ratio for WAF and CRS rows (default: 1.30)
  OXIBELT_PERF_REGRESSION_GATE_MODE   fail or warn for targeted regression gates (default: fail)
  OXIBELT_PERF_OXIBELT_BASELINE_SCENARIO
                                      test-only OxiBelt baseline fixture override
  OXIBELT_PERF_OXIBELT_AGGRESSIVE_SCENARIO
                                      test-only OxiBelt aggressive long-run fixture override
  OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO
                                      test-only OxiBelt TLS handshake fixture override
  OXIBELT_PERF_POOL_CAPS             comma-separated direct-H1 idle pool caps for pool-concurrency rows
  OXIBELT_PERF_POOL_CONCURRENCY_PRESETS
                                      comma-separated probe concurrency values for pool-concurrency rows
  OXIBELT_PERF_PROFILE_LABEL         exact load label to record with host perf, for diagnostics only
  OXIBELT_PERF_PROFILE_FREQUENCY     perf sampling frequency for diagnostic profiling (default: 99)
  OXIBELT_PERF_PROFILE_CALL_GRAPH    perf call graph mode for diagnostic profiling (default: dwarf,8192)
  OXIBELT_PERF_DIAGNOSTIC_PROFILES   run separate profile-only replay rows, 1 or 0 (default: 0)
  OXIBELT_PERF_DIAGNOSTIC_PROFILE_MODE
                                      cpu, memory, or cpu-memory (default: cpu-memory)
  OXIBELT_PERF_DIAGNOSTIC_EVENT      perf event for diagnostic CPU replay (default: cpu-clock)
  OXIBELT_PERF_DIAGNOSTIC_FREQUENCY  perf frequency for diagnostic CPU replay (default: 49)
  OXIBELT_PERF_DIAGNOSTIC_GATE_MODE  fail or warn for diagnostic profiling failures (default: warn)
  OXIBELT_PERF_DIAGNOSTIC_COMPRESS   compress bulky perf artifacts with zstd, 1 or 0 (default: 1)
  OXIBELT_TEST_ARTIFACT_DIR        copy summary, results, logs, probe logs, configs, and stats here
  KEEP_TEST_ARTIFACTS=1            keep tests/.tmp performance work directory
EOF
}

profile="smoke"
serving_type="all"
comparators="oxibelt,nginx,caddy,openresty"

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
  all|reverse-proxy|static-files|oxibelt-features|oxibelt-soak-stress|accept-multipliers|remote-signer|pool-concurrency|runtime-direct-h1|metrics-mode|oxibelt-aggressive-long-run) ;;
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
profiles_dir="${work_dir}/profiles"
profile_cpu_dir="${profiles_dir}/cpu"
profile_memory_dir="${profiles_dir}/memory"
configs_dir="${work_dir}/configs"
tls_dir="${work_dir}/proxy-tls"
static_dir="${work_dir}/static"
results_jsonl="${work_dir}/results.jsonl"
results_json="${work_dir}/results.json"
external_results_jsonl="${work_dir}/external-results.jsonl"
external_results_json="${work_dir}/external-results.json"
profile_results_jsonl="${work_dir}/profile-results.jsonl"
profile_results_json="${work_dir}/profile-results.json"
summary_md="${work_dir}/summary.md"
stats_jsonl="${work_dir}/docker-stats.jsonl"
resource_snapshots_jsonl="${work_dir}/resource-snapshots.jsonl"
resource_drift_json="${work_dir}/resource-drift.json"
external_h2load_dir="${work_dir}/external-h2load"
external_oha_dir="${work_dir}/external-oha"
external_wrk_dir="${work_dir}/external-wrk"
network_name="oxibelt-perf-${run_id}"
test_label="oxibelt.test.run=${run_id}"
perf_probe_image="${OXIBELT_PERF_PROBE_IMAGE:-oxibelt/perf-probe:${run_id}}"
external_benchmark_image="${OXIBELT_EXTERNAL_BENCHMARK_IMAGE:-oxibelt/external-benchmarks:${run_id}}"
oxibelt_image="${OXIBELT_DOCKER_IMAGE:-oxibelt/perf-proxy:${run_id}}"
nginx_image="${OXIBELT_NGINX_IMAGE:-nginx:mainline-alpine}"
caddy_image="${OXIBELT_CADDY_IMAGE:-caddy:2-alpine}"
openresty_image="${OXIBELT_OPENRESTY_IMAGE:-openresty/openresty:1.31.1.1-1-alpine}"
nginx_h3_mode_override="${OXIBELT_NGINX_H3_MODE:-auto}"
remove_perf_probe_image=0
remove_external_benchmark_image=0
remove_oxibelt_image=0
active_proxy_container=""
active_remote_signer_container=""
active_remote_signer_volume=""
active_remote_signer_cert_volume=""
external_summary_started=0
external_h2load_h3_zero_deferred=0
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
aggressive_stress_seconds="${OXIBELT_PERF_AGGRESSIVE_STRESS_SECONDS:-180}"
max_p99_ms="${OXIBELT_PERF_MAX_P99_MS:-10000}"
max_load_errors_per_million="${OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION:-100}"
tcp_baseline_max_p50_ms="${OXIBELT_PERF_TCP_BASELINE_MAX_P50_MS:-25}"
tcp_baseline_max_p99_ms="${OXIBELT_PERF_TCP_BASELINE_MAX_P99_MS:-45}"
static_16k_h1c_min_caddy_ratio="${OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO:-0.80}"
h1_fast_path_min_hit_rate="${OXIBELT_PERF_H1_FAST_PATH_MIN_HIT_RATE:-0.99}"
waf_enforcing_min_rps="${OXIBELT_PERF_WAF_ENFORCING_MIN_RPS:-10000}"
crs_enforcing_min_rps="${OXIBELT_PERF_CRS_ENFORCING_MIN_RPS:-8000}"
waf_crs_max_enforce_p99_ratio="${OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO:-1.30}"
regression_gate_mode="${OXIBELT_PERF_REGRESSION_GATE_MODE:-fail}"
external_benchmarks="${OXIBELT_EXTERNAL_BENCHMARKS:-1}"
external_benchmark_tools="${OXIBELT_EXTERNAL_BENCHMARK_TOOLS:-h2load,oha,wrk}"
external_benchmark_gate_mode="${OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE:-warn}"
external_oha_qps="${OXIBELT_EXTERNAL_OHA_QPS:-1000}"
external_oha_max_p99_ms="${OXIBELT_EXTERNAL_OHA_MAX_P99_MS:-250}"
external_oha_max_error_rate="${OXIBELT_EXTERNAL_OHA_MAX_ERROR_RATE:-0}"
amd64_target_cpu="${OXIBELT_AMD64_TARGET_CPU:-unspecified}"
oxibelt_baseline_scenario="${OXIBELT_PERF_OXIBELT_BASELINE_SCENARIO:-baseline}"
oxibelt_aggressive_scenario="${OXIBELT_PERF_OXIBELT_AGGRESSIVE_SCENARIO:-baseline-aggressive-long-run}"
oxibelt_handshake_scenario="${OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO:-baseline-accept-1}"
pool_experiment_caps="${OXIBELT_PERF_POOL_CAPS:-128,256,512}"
pool_experiment_concurrency_presets="${OXIBELT_PERF_POOL_CONCURRENCY_PRESETS:-16,64,256}"
resource_max_memory_delta_bytes="${OXIBELT_PERF_RESOURCE_MAX_MEMORY_DELTA_BYTES:-268435456}"
resource_max_fd_delta="${OXIBELT_PERF_RESOURCE_MAX_FD_DELTA:-256}"
resource_max_task_delta="${OXIBELT_PERF_RESOURCE_MAX_TASK_DELTA:-64}"
resource_settle_seconds="${OXIBELT_PERF_RESOURCE_SETTLE_SECONDS:-30}"
profile_label="${OXIBELT_PERF_PROFILE_LABEL:-}"
profile_frequency="${OXIBELT_PERF_PROFILE_FREQUENCY:-99}"
profile_call_graph="${OXIBELT_PERF_PROFILE_CALL_GRAPH:-dwarf,8192}"
diagnostic_profiles="${OXIBELT_PERF_DIAGNOSTIC_PROFILES:-0}"
diagnostic_profile_mode="${OXIBELT_PERF_DIAGNOSTIC_PROFILE_MODE:-cpu-memory}"
diagnostic_profile_event="${OXIBELT_PERF_DIAGNOSTIC_EVENT:-cpu-clock}"
diagnostic_profile_frequency="${OXIBELT_PERF_DIAGNOSTIC_FREQUENCY:-49}"
diagnostic_profile_gate_mode="${OXIBELT_PERF_DIAGNOSTIC_GATE_MODE:-warn}"
diagnostic_profile_compress="${OXIBELT_PERF_DIAGNOSTIC_COMPRESS:-1}"
diagnostic_profile_warning_count=0
docker_command="${OXIBELT_DOCKER_COMMAND:-docker}"

if [[ ! "${max_load_errors_per_million}" =~ ^(0|[1-9][0-9]*)([.][0-9]+)?$ ]]; then
  echo "OXIBELT_PERF_MAX_LOAD_ERRORS_PER_MILLION must be a non-negative number; got '${max_load_errors_per_million}'" >&2
  exit 2
fi
case "${external_benchmarks}" in
  0|1) ;;
  *)
    echo "OXIBELT_EXTERNAL_BENCHMARKS must be 1 or 0; got '${external_benchmarks}'" >&2
    exit 2
    ;;
esac
case "${external_benchmark_gate_mode}" in
  fail|warn) ;;
  *)
    echo "OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE must be fail or warn; got '${external_benchmark_gate_mode}'" >&2
    exit 2
    ;;
esac
if [[ ! "${external_oha_qps}" =~ ^[1-9][0-9]*$ ]]; then
  echo "OXIBELT_EXTERNAL_OHA_QPS must be a positive integer; got '${external_oha_qps}'" >&2
  exit 2
fi
if [[ ! "${external_oha_max_p99_ms}" =~ ^(0|[1-9][0-9]*)([.][0-9]+)?$ ]]; then
  echo "OXIBELT_EXTERNAL_OHA_MAX_P99_MS must be a non-negative number; got '${external_oha_max_p99_ms}'" >&2
  exit 2
fi
if [[ ! "${external_oha_max_error_rate}" =~ ^(0|0[.][0-9]+|1|1[.]0+)$ ]]; then
  echo "OXIBELT_EXTERNAL_OHA_MAX_ERROR_RATE must be a number from 0.0 to 1.0; got '${external_oha_max_error_rate}'" >&2
  exit 2
fi
for integer_env in \
  "OXIBELT_PERF_AGGRESSIVE_STRESS_SECONDS:${aggressive_stress_seconds}" \
  "OXIBELT_PERF_RESOURCE_MAX_MEMORY_DELTA_BYTES:${resource_max_memory_delta_bytes}" \
  "OXIBELT_PERF_RESOURCE_MAX_FD_DELTA:${resource_max_fd_delta}" \
  "OXIBELT_PERF_RESOURCE_MAX_TASK_DELTA:${resource_max_task_delta}"; do
  integer_name="${integer_env%%:*}"
  integer_value="${integer_env#*:}"
  if [[ ! "${integer_value}" =~ ^[1-9][0-9]*$ ]]; then
    echo "${integer_name} must be a positive integer; got '${integer_value}'" >&2
    exit 2
  fi
done
if [[ ! "${resource_settle_seconds}" =~ ^(0|[1-9][0-9]*)$ ]]; then
  echo "OXIBELT_PERF_RESOURCE_SETTLE_SECONDS must be a non-negative integer; got '${resource_settle_seconds}'" >&2
  exit 2
fi
if [[ ! "${static_16k_h1c_min_caddy_ratio}" =~ ^(0|[1-9][0-9]*)([.][0-9]+)?$ ]]; then
  echo "OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO must be a non-negative number; got '${static_16k_h1c_min_caddy_ratio}'" >&2
  exit 2
fi
if [[ ! "${h1_fast_path_min_hit_rate}" =~ ^(0|[1-9][0-9]*)([.][0-9]+)?$ ]]; then
  echo "OXIBELT_PERF_H1_FAST_PATH_MIN_HIT_RATE must be a non-negative number; got '${h1_fast_path_min_hit_rate}'" >&2
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
case "${regression_gate_mode}" in
  fail|warn) ;;
  *)
    echo "OXIBELT_PERF_REGRESSION_GATE_MODE must be fail or warn; got '${regression_gate_mode}'" >&2
    exit 2
    ;;
esac
case "${nginx_h3_mode_override}" in
  auto|required|optional|disabled) ;;
  *)
    echo "OXIBELT_NGINX_H3_MODE must be auto, required, optional, or disabled; got '${nginx_h3_mode_override}'" >&2
    exit 2
    ;;
esac
case "${diagnostic_profiles}" in
  0|1) ;;
  *)
    echo "OXIBELT_PERF_DIAGNOSTIC_PROFILES must be 1 or 0; got '${diagnostic_profiles}'" >&2
    exit 2
    ;;
esac
case "${diagnostic_profile_mode}" in
  cpu|memory|cpu-memory) ;;
  *)
    echo "OXIBELT_PERF_DIAGNOSTIC_PROFILE_MODE must be cpu, memory, or cpu-memory; got '${diagnostic_profile_mode}'" >&2
    exit 2
    ;;
esac
case "${diagnostic_profile_gate_mode}" in
  fail|warn) ;;
  *)
    echo "OXIBELT_PERF_DIAGNOSTIC_GATE_MODE must be fail or warn; got '${diagnostic_profile_gate_mode}'" >&2
    exit 2
    ;;
esac
case "${diagnostic_profile_compress}" in
  0|1) ;;
  *)
    echo "OXIBELT_PERF_DIAGNOSTIC_COMPRESS must be 1 or 0; got '${diagnostic_profile_compress}'" >&2
    exit 2
    ;;
esac
if [[ ! "${diagnostic_profile_frequency}" =~ ^[1-9][0-9]*$ ]]; then
  echo "OXIBELT_PERF_DIAGNOSTIC_FREQUENCY must be a positive integer; got '${diagnostic_profile_frequency}'" >&2
  exit 2
fi
if [[ -z "${diagnostic_profile_event}" ]]; then
  echo "OXIBELT_PERF_DIAGNOSTIC_EVENT must not be empty when diagnostic profiling is configured" >&2
  exit 2
fi
if [[ -z "${docker_command}" ]]; then
  echo "OXIBELT_DOCKER_COMMAND must not be empty" >&2
  exit 2
fi

docker() {
  command "${docker_command}" "$@"
}

cleanup() {
  docker ps -aq --filter "label=${test_label}" | xargs -r "${docker_command}" rm -f >/dev/null 2>&1 || true
  docker network rm "${network_name}" >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=${test_label}" | xargs -r "${docker_command}" volume rm >/dev/null 2>&1 || true
  if [[ "${remove_perf_probe_image}" == "1" ]]; then
    docker rmi -f "${perf_probe_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${remove_external_benchmark_image}" == "1" ]]; then
    docker rmi -f "${external_benchmark_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${remove_oxibelt_image}" == "1" ]]; then
    docker rmi -f "${oxibelt_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${KEEP_TEST_ARTIFACTS:-0}" != "1" ]]; then
    rm -rf "${work_dir}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "${logs_dir}" "${probe_logs_dir}" "${profiles_dir}" "${profile_cpu_dir}" "${profile_memory_dir}" "${configs_dir}" "${tls_dir}" "${static_dir}" "${external_h2load_dir}" "${external_oha_dir}" "${external_wrk_dir}"
: >"${results_jsonl}"
: >"${external_results_jsonl}"
: >"${profile_results_jsonl}"
: >"${stats_jsonl}"
: >"${resource_snapshots_jsonl}"

require_tool() {
  if ! type -P "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_tool "${docker_command}"
require_tool jq
require_tool openssl
if [[ -n "${profile_label}" ]]; then
  require_tool perf
  if [[ ! "${profile_frequency}" =~ ^[1-9][0-9]*$ ]]; then
    echo "OXIBELT_PERF_PROFILE_FREQUENCY must be a positive integer; got '${profile_frequency}'" >&2
    exit 2
  fi
  if [[ -z "${profile_call_graph}" ]]; then
    echo "OXIBELT_PERF_PROFILE_CALL_GRAPH must not be empty when OXIBELT_PERF_PROFILE_LABEL is set" >&2
    exit 2
  fi
fi

IFS=',' read -r -a comparator_list <<<"${comparators}"
IFS=',' read -r -a external_tool_list <<<"${external_benchmark_tools}"

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

has_external_tool() {
  local wanted="$1"
  local item
  for item in "${external_tool_list[@]}"; do
    if [[ "${item}" == "${wanted}" ]]; then
      return 0
    fi
  done
  return 1
}

external_benchmark_serving_type_enabled() {
  [[ "${external_benchmarks}" == "1" ]] || return 1
  case "${serving_type}" in
    all|reverse-proxy) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ "${external_benchmarks}" == "1" ]]; then
  for external_tool in "${external_tool_list[@]}"; do
    case "${external_tool}" in
      h2load|oha|wrk) ;;
      "")
        echo "OXIBELT_EXTERNAL_BENCHMARK_TOOLS must not contain empty entries" >&2
        exit 2
        ;;
      *)
        echo "OXIBELT_EXTERNAL_BENCHMARK_TOOLS entries must be h2load, oha, or wrk; got '${external_tool}'" >&2
        exit 2
        ;;
    esac
  done
fi

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
DNS.5 = openresty
DNS.6 = localhost
DNS.7 = perf-upstream-h2
DNS.8 = example.test
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

retry_command() {
  local attempts="$1"
  shift
  local delay=5
  local attempt status

  for attempt in $(seq 1 "${attempts}"); do
    "$@" && return 0
    status=$?
    if [[ "${attempt}" == "${attempts}" ]]; then
      return "${status}"
    fi
    printf 'Command failed with status %s; retrying in %ss (%s/%s): %s\n' \
      "${status}" "${delay}" "${attempt}" "${attempts}" "$*" >&2
    sleep "${delay}"
    delay=$((delay * 2))
  done
}

build_perf_probe_image() {
  if [[ -n "${OXIBELT_PERF_PROBE_IMAGE:-}" ]]; then
    return 0
  fi

  remove_perf_probe_image=1
  for base_image in rust:1.96.0-trixie debian:trixie-slim; do
    retry_command 3 docker pull "${base_image}" \
      || fail_with_diagnostics "failed to pull performance probe base image ${base_image}"
  done
  retry_command 3 docker build \
    -t "${perf_probe_image}" \
    -f "${repo_root}/tests/docker/perf_probe/Dockerfile" \
    "${repo_root}/tests/docker/perf_probe" >/dev/null \
    || fail_with_diagnostics "failed to build performance probe image ${perf_probe_image}"
}

build_external_benchmark_image() {
  if ! external_benchmark_serving_type_enabled; then
    return 0
  fi
  if [[ -n "${OXIBELT_EXTERNAL_BENCHMARK_IMAGE:-}" ]]; then
    return 0
  fi

  remove_external_benchmark_image=1
  local base_image
  for base_image in rust:1.96.0-trixie debian:trixie debian:trixie-slim; do
    retry_command 3 docker pull "${base_image}" >/dev/null \
      || fail_with_diagnostics "failed to pull external benchmark base image ${base_image}"
  done
  retry_command 3 docker build \
    -t "${external_benchmark_image}" \
    -f "${repo_root}/tests/docker/external_benchmarks/Dockerfile" \
    "${repo_root}/tests/docker/external_benchmarks" >/dev/null \
    || fail_with_diagnostics "failed to build external benchmark image ${external_benchmark_image}"
}

fail_with_diagnostics() {
  echo "$1" >&2
  collect_logs
  finalize_results || true
  copy_artifacts
  exit 1
}

handle_regression_gate_violation() {
  local message="$1"
  if [[ "${regression_gate_mode}" == "warn" ]]; then
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
      echo "::warning title=Docker performance regression gate::${message}" >&2
    else
      echo "Docker performance regression gate warning: ${message}" >&2
    fi
    return
  fi

  fail_with_diagnostics "${message}"
}

handle_external_benchmark_failure() {
  local message="$1"
  if [[ "${external_benchmark_gate_mode}" == "warn" ]]; then
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
      echo "::warning title=External benchmark validation::${message}" >&2
    else
      echo "External benchmark validation warning: ${message}" >&2
    fi
    return
  fi

  fail_with_diagnostics "${message}"
}

flush_external_h2load_h3_zero_failures() {
  if [[ "${external_h2load_h3_zero_deferred}" != "1" || ! -s "${external_results_jsonl}" ]]; then
    return
  fi

  local failures
  failures="$(jq -s -r '
    def zero:
      .tool == "h2load"
      and .protocol == "h3"
      and .status == "fail"
      and .reason == "h2load produced no completed requests"
      and ((.requests // 0) == 0);
    def key: [(.amd64_target_cpu // "unknown"), (.scenario // "unknown"), (.protocol // "unknown")];
    [.[] | select(zero)] as $rows
    | ($rows
        | group_by(key)
        | map(select((map(.comparator) | unique) as $comparators
          | (($comparators | index("oxibelt")) and ($comparators | index("nginx")) and ($comparators | index("caddy")))))
        | map(.[0] | key | @json)) as $diagnostic_keys
    | $rows[]
    | select((key | @json) as $row_key | ($diagnostic_keys | index($row_key) | not))
    | "h2load h3 external benchmark failed for " + (.comparator // "unknown") + ": " + (.reason // "unknown failure")
  ' "${external_results_jsonl}")"
  while IFS= read -r failure; do
    [[ -n "${failure}" ]] || continue
    handle_external_benchmark_failure "${failure}"
  done <<<"${failures}"
}

handle_diagnostic_profile_failure() {
  local message="$1"
  if [[ "${diagnostic_profile_gate_mode}" == "warn" ]]; then
    diagnostic_profile_warning_count=$((diagnostic_profile_warning_count + 1))
    return
  fi

  fail_with_diagnostics "${message}"
}

diagnostic_comparator_label() {
  return 1
}

flush_diagnostic_profile_warnings() {
  if (( diagnostic_profile_warning_count > 0 )); then
    echo "Docker performance diagnostic profiling reported ${diagnostic_profile_warning_count} unavailable sample(s); see profile-results.json and profiles/" >&2
  fi
}

diagnostic_profile_mode_has_cpu() {
  [[ "${diagnostic_profile_mode}" == "cpu" || "${diagnostic_profile_mode}" == "cpu-memory" ]]
}

diagnostic_profile_mode_has_memory() {
  [[ "${diagnostic_profile_mode}" == "memory" || "${diagnostic_profile_mode}" == "cpu-memory" ]]
}

diagnostic_profile_comparator_from_label() {
  local label="$1"
  case "${label}" in
    oxibelt*) echo oxibelt ;;
    nginx*) echo nginx ;;
    caddy*) echo caddy ;;
    openresty*) echo openresty ;;
    *) echo unknown ;;
  esac
}

append_profile_result() {
  local json="$1"
  json="$(jq -c --arg target "${amd64_target_cpu}" '. + {amd64_target_cpu: $target}' <<<"${json}")"
  printf '%s\n' "${json}" >>"${profile_results_jsonl}"
}

collect_logs() {
  mkdir -p "${logs_dir}"
  local container
  while read -r container; do
    [[ -z "${container}" ]] && continue
    docker logs "${container}" >"${logs_dir}/${container}.log" 2>&1 || true
  done < <(docker ps -a --filter "label=${test_label}" --format '{{.Names}}')
}

diagnostic_host_pids_csv() {
  local containers=()
  local container root_pid child grandchild csv=""
  if [[ -n "${active_proxy_container}" ]]; then
    containers+=("${active_proxy_container}")
  fi
  if [[ -n "${active_remote_signer_container}" ]]; then
    containers+=("${active_remote_signer_container}")
  fi

  for container in "${containers[@]}"; do
    root_pid="$(docker inspect -f '{{.State.Pid}}' "${container}" 2>/dev/null || true)"
    [[ "${root_pid}" =~ ^[1-9][0-9]*$ ]] || continue
    if [[ -z "${csv}" ]]; then
      csv="${root_pid}"
    else
      csv="${csv},${root_pid}"
    fi
    if command -v pgrep >/dev/null 2>&1; then
      while read -r child; do
        [[ "${child}" =~ ^[1-9][0-9]*$ ]] || continue
        csv="${csv},${child}"
        while read -r grandchild; do
          [[ "${grandchild}" =~ ^[1-9][0-9]*$ ]] || continue
          csv="${csv},${grandchild}"
        done < <(pgrep -P "${child}" 2>/dev/null || true)
      done < <(pgrep -P "${root_pid}" 2>/dev/null || true)
    fi
  done
  echo "${csv}"
}

diagnostic_container_resource_json() {
  local container="$1"
  local role="$2"
  local sample="$3"
  local values rss_kb fd_count task_count threads memory_bytes
  if [[ -z "${container}" ]]; then
    jq -cn --arg role "${role}" --arg sample "${sample}" \
      '{sample: $sample, role: $role, available: false, reason: "container is not active"}'
    return
  fi

  values="$(docker exec "${container}" sh -c '
    rss=0
    fds=0
    tasks=0
    threads=0
    for d in /proc/[0-9]*; do
      [ -r "$d/status" ] || continue
      r="$(awk "/^VmRSS:/{print \$2}" "$d/status" 2>/dev/null || true)"
      t="$(awk "/^Threads:/{print \$2}" "$d/status" 2>/dev/null || true)"
      rss=$((rss + ${r:-0}))
      threads=$((threads + ${t:-0}))
      tasks=$((tasks + 1))
      if [ -d "$d/fd" ]; then
        c="$(ls -1 "$d/fd" 2>/dev/null | wc -l || true)"
        fds=$((fds + ${c:-0}))
      fi
    done
    printf "%s %s %s %s\n" "$rss" "$fds" "$tasks" "$threads"
  ' 2>/dev/null || echo "0 0 0 0")"
  read -r rss_kb fd_count task_count threads <<<"${values}"
  memory_bytes=$(( ${rss_kb:-0} * 1024 ))
  jq -cn \
    --arg sample "${sample}" \
    --arg role "${role}" \
    --arg container "${container}" \
    --argjson memory_rss_bytes "${memory_bytes}" \
    --argjson fd_count "${fd_count:-0}" \
    --argjson task_count "${task_count:-0}" \
    --argjson thread_count "${threads:-0}" \
    '{
      sample: $sample,
      role: $role,
      container: $container,
      available: true,
      memory_rss_bytes: $memory_rss_bytes,
      fd_count: $fd_count,
      task_count: $task_count,
      thread_count: $thread_count
    }'
}

diagnostic_collect_resources_json() {
  local sample="$1"
  local proxy_json remote_json
  proxy_json="$(diagnostic_container_resource_json "${active_proxy_container}" proxy "${sample}")"
  if [[ -n "${active_remote_signer_container}" ]]; then
    remote_json="$(diagnostic_container_resource_json "${active_remote_signer_container}" remote_signer "${sample}")"
    jq -cn --argjson proxy "${proxy_json}" --argjson remote "${remote_json}" '[$proxy, $remote]'
  else
    jq -cn --argjson proxy "${proxy_json}" '[$proxy]'
  fi
}

write_heap_evidence() {
  local comparator="$1"
  local heap_dir="$2"
  local reason="$3"
  mkdir -p "${heap_dir}"
  jq -n \
    --arg comparator "${comparator}" \
    --arg reason "${reason}" \
    '{
      schema_version: 1,
      comparator: $comparator,
      status: "unsupported",
      unsupported_heap_reason: $reason
    }' >"${heap_dir}/unsupported.json"
  if [[ -n "${active_proxy_container}" ]]; then
    docker exec "${active_proxy_container}" sh -c 'cat /proc/1/smaps_rollup 2>/dev/null || true' \
      >"${heap_dir}/smaps-rollup-after.txt" 2>/dev/null || true
  fi
}

diagnostic_binary_path_for_comparator() {
  local comparator="$1"
  case "${comparator}" in
    oxibelt) echo /usr/local/bin/oxibelt ;;
    nginx) echo /usr/sbin/nginx ;;
    caddy) echo /usr/bin/caddy ;;
    openresty) echo /usr/local/openresty/nginx/sbin/nginx ;;
    *) echo "" ;;
  esac
}

write_unavailable_flamegraph() {
  local path="$1"
  local reason="$2"
  printf '%s\n' \
    '<svg xmlns="http://www.w3.org/2000/svg" width="900" height="80">' \
    '<rect width="100%" height="100%" fill="#f8f8f8"/>' \
    "<text x=\"16\" y=\"44\" font-family=\"sans-serif\" font-size=\"16\">${reason}</text>" \
    '</svg>' >"${path}"
}

compress_profile_artifact() {
  local path="$1"
  if [[ "${diagnostic_profile_compress}" == "1" && -s "${path}" ]]; then
    if command -v zstd >/dev/null 2>&1; then
      zstd -f -q "${path}" >/dev/null 2>&1 && {
        rm -f "${path}"
        echo "${path}.zst"
        return
      }
    fi
  fi
  echo "${path}"
}

profile_relpath() {
  local path="$1"
  printf '%s\n' "${path#"${work_dir}/"}"
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

sample_resource_snapshot() {
  local sample="$1"
  local container="${active_proxy_container}"
  local status rss_kb threads fd_count task_count memory_bytes json
  if [[ -z "${container}" ]]; then
    return
  fi
  status="$(docker exec "${container}" sh -c 'awk "/^VmRSS:/{rss=\$2} /^Threads:/{threads=\$2} END{print rss+0, threads+0}" /proc/1/status' 2>/dev/null || echo "0 0")"
  read -r rss_kb threads <<<"${status}"
  fd_count="$(docker exec "${container}" sh -c 'ls -1 /proc/1/fd 2>/dev/null | wc -l' 2>/dev/null | tr -d '[:space:]' || echo 0)"
  task_count="$(docker exec "${container}" sh -c 'ls -1 /proc/1/task 2>/dev/null | wc -l' 2>/dev/null | tr -d '[:space:]' || echo 0)"
  memory_bytes=$(( rss_kb * 1024 ))
  json="$(jq -cn \
    --arg sample "${sample}" \
    --arg container "${container}" \
    --argjson memory_rss_bytes "${memory_bytes}" \
    --argjson fd_count "${fd_count:-0}" \
    --argjson task_count "${task_count:-0}" \
    --argjson thread_count "${threads:-0}" \
    '{sample: $sample, container: $container, memory_rss_bytes: $memory_rss_bytes, fd_count: $fd_count, task_count: $task_count, thread_count: $thread_count}')"
  printf '%s\n' "${json}" >>"${resource_snapshots_jsonl}"
}

assert_resource_drift() {
  local before_label="$1"
  local after_label="$2"
  local before after memory_delta fd_delta task_delta thread_delta max_taskish_delta
  before="$(jq -c --arg sample "${before_label}" 'select(.sample == $sample)' "${resource_snapshots_jsonl}" | tail -n 1)"
  after="$(jq -c --arg sample "${after_label}" 'select(.sample == $sample)' "${resource_snapshots_jsonl}" | tail -n 1)"
  if [[ -z "${before}" || -z "${after}" ]]; then
    fail_with_diagnostics "missing resource snapshots for drift gate (${before_label} -> ${after_label})"
  fi
  jq -n \
    --arg before_label "${before_label}" \
    --arg after_label "${after_label}" \
    --argjson before "${before}" \
    --argjson after "${after}" \
    --argjson max_memory_delta_bytes "${resource_max_memory_delta_bytes}" \
    --argjson max_fd_delta "${resource_max_fd_delta}" \
    --argjson max_task_delta "${resource_max_task_delta}" \
    '{
      before_label: $before_label,
      after_label: $after_label,
      before: $before,
      after: $after,
      deltas: {
        memory_rss_bytes: (($after.memory_rss_bytes // 0) - ($before.memory_rss_bytes // 0)),
        fd_count: (($after.fd_count // 0) - ($before.fd_count // 0)),
        task_count: (($after.task_count // 0) - ($before.task_count // 0)),
        thread_count: (($after.thread_count // 0) - ($before.thread_count // 0))
      },
      limits: {
        memory_rss_bytes: $max_memory_delta_bytes,
        fd_count: $max_fd_delta,
        task_count: $max_task_delta,
        thread_count: $max_task_delta
      }
    }' >"${resource_drift_json}"
  memory_delta="$(jq -r '.deltas.memory_rss_bytes' "${resource_drift_json}")"
  fd_delta="$(jq -r '.deltas.fd_count' "${resource_drift_json}")"
  task_delta="$(jq -r '.deltas.task_count' "${resource_drift_json}")"
  thread_delta="$(jq -r '.deltas.thread_count' "${resource_drift_json}")"
  max_taskish_delta="${task_delta}"
  if (( thread_delta > max_taskish_delta )); then
    max_taskish_delta="${thread_delta}"
  fi
  printf '| `%s` | `resource` | `procfs` | memory %+d bytes, fd %+d, tasks %+d, threads %+d | limits: memory %s bytes, fd %s, task/thread %s |\n' \
    "oxibelt-resource-drift" "${memory_delta}" "${fd_delta}" "${task_delta}" "${thread_delta}" \
    "${resource_max_memory_delta_bytes}" "${resource_max_fd_delta}" "${resource_max_task_delta}" >>"${summary_md}"
  if (( memory_delta > resource_max_memory_delta_bytes )); then
    fail_with_diagnostics "OxiBelt aggressive long-run RSS drift exceeded gate (${memory_delta} > ${resource_max_memory_delta_bytes} bytes)"
  fi
  if (( fd_delta > resource_max_fd_delta )); then
    fail_with_diagnostics "OxiBelt aggressive long-run FD drift exceeded gate (${fd_delta} > ${resource_max_fd_delta})"
  fi
  if (( max_taskish_delta > resource_max_task_delta )); then
    fail_with_diagnostics "OxiBelt aggressive long-run task/thread drift exceeded gate (${max_taskish_delta} > ${resource_max_task_delta})"
  fi
}

profile_artifact_name() {
  local name="$1"
  name="${name//[^A-Za-z0-9_.-]/_}"
  if [[ -z "${name}" ]]; then
    echo profile
  else
    echo "${name}"
  fi
}

should_profile_load() {
  local label="$1"
  [[ -n "${profile_label}" && "${label}" == "${profile_label}" ]]
}

active_oxibelt_host_pid() {
  local label="$1"
  if [[ -z "${active_proxy_container}" ]]; then
    fail_with_diagnostics "profiling requested for ${label}, but no active OxiBelt container is running"
  fi

  local pid
  pid="$(docker inspect -f '{{.State.Pid}}' "${active_proxy_container}" 2>/dev/null || true)"
  if [[ ! "${pid}" =~ ^[1-9][0-9]*$ ]]; then
    fail_with_diagnostics "profiling requested for ${label}, but OxiBelt host PID was not available"
  fi

  if [[ "$(docker inspect -f '{{.State.Running}}' "${active_proxy_container}" 2>/dev/null || echo false)" != "true" ]]; then
    fail_with_diagnostics "profiling requested for ${label}, but OxiBelt container is not running"
  fi

  echo "${pid}"
}

profile_duration_seconds() {
  local duration="$1"
  jq -n -r --arg duration "${duration}" --arg warmup "${warmup_seconds}" \
    '($duration | tonumber) + ($warmup | tonumber) + 2'
}

run_diagnostic_profile_replay() {
  local label="$1"
  local duration="$2"
  local protocol="$3"
  shift 3
  local probe_args=("$@")
  local comparator profile_name profile_seconds started_at finished_at
  local status="pass" reason="" replay_status=0 replay_json=""
  local cpu_json memory_json before_json after_json resource_path memory_metadata_path heap_dir heap_reason
  local perf_pid="" perf_status=0 pid_csv="" perf_data="" perf_report="" perf_script="" perf_stderr="" perf_flamegraph="" perf_metadata=""
  local perf_data_final="" perf_script_final="" copied_binary="" binary_path buildid_dir
  [[ "${diagnostic_profiles:-0}" == "1" ]] || return 0

  comparator="$(diagnostic_profile_comparator_from_label "${label}")"
  profile_name="$(profile_artifact_name "${label}")"
  profile_seconds="$(profile_duration_seconds "${duration}")"
  started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  cpu_json="$(jq -cn '{enabled: false}')"
  memory_json="$(jq -cn '{enabled: false}')"

  if diagnostic_profile_mode_has_memory; then
    before_json="$(diagnostic_collect_resources_json before)"
  fi

  if diagnostic_profile_mode_has_cpu; then
    mkdir -p "${profile_cpu_dir}"
    perf_data="${profile_cpu_dir}/${profile_name}.perf.data"
    perf_report="${profile_cpu_dir}/${profile_name}.perf.report.txt"
    perf_script="${profile_cpu_dir}/${profile_name}.perf.script.txt"
    perf_stderr="${profile_cpu_dir}/${profile_name}.perf.stderr.log"
    perf_flamegraph="${profile_cpu_dir}/${profile_name}.flamegraph.svg"
    perf_metadata="${profile_cpu_dir}/${profile_name}.metadata.json"
    buildid_dir="${profile_cpu_dir}/.build-id"
    mkdir -p "${buildid_dir}"
    : >"${perf_stderr}"
    pid_csv="$(diagnostic_host_pids_csv)"
    binary_path="$(diagnostic_binary_path_for_comparator "${comparator}")"
    if [[ -n "${binary_path}" && -n "${active_proxy_container}" ]]; then
      copied_binary="${profile_cpu_dir}/${profile_name}.${comparator}.binary"
      docker cp "${active_proxy_container}:${binary_path}" "${copied_binary}" >>"${perf_stderr}" 2>&1 || copied_binary=""
      if [[ -n "${copied_binary}" ]]; then
        chmod 0644 "${copied_binary}" || true
        PERF_BUILDID_DIR="${buildid_dir}" perf buildid-cache --add "${copied_binary}" >>"${perf_stderr}" 2>&1 || true
      fi
    fi
    if ! command -v perf >/dev/null 2>&1; then
      status="fail"
      reason="perf is not installed for diagnostic profiling"
    elif [[ -z "${pid_csv}" ]]; then
      status="fail"
      reason="no active host PIDs were available for diagnostic profiling"
    else
      perf record \
        --event "${diagnostic_profile_event}" \
        --freq "${diagnostic_profile_frequency}" \
        --call-graph "${profile_call_graph}" \
        --pid "${pid_csv}" \
        --output "${perf_data}" \
        -- sleep "${profile_seconds}" >>"${perf_stderr}" 2>&1 &
      perf_pid=$!
      sleep 0.2
    fi
  fi

  replay_json="$(run_probe_json "${probe_args[@]}")" || replay_status=$?
  if [[ "${replay_status}" != "0" ]]; then
    status="fail"
    if [[ -z "${reason}" ]]; then
      reason="diagnostic replay exited with status ${replay_status}"
    fi
  fi

  if [[ -n "${perf_pid}" ]]; then
    if kill -0 "${perf_pid}" >/dev/null 2>&1; then
      kill -INT "${perf_pid}" >/dev/null 2>&1 || true
    fi
    wait "${perf_pid}" || perf_status=$?
    if [[ "${perf_status}" != "0" && "${perf_status}" != "130" && "${perf_status}" != "143" ]]; then
      status="fail"
      reason="${reason:-perf record failed with status ${perf_status}}"
    elif [[ ! -s "${perf_data}" ]]; then
      status="fail"
      reason="${reason:-perf record produced no data}"
    else
      PERF_BUILDID_DIR="${buildid_dir}" perf report --stdio --input "${perf_data}" >"${perf_report}" 2>>"${perf_stderr}" \
        || {
          status="fail"
          reason="${reason:-perf report failed}"
        }
      PERF_BUILDID_DIR="${buildid_dir}" perf script --input "${perf_data}" >"${perf_script}" 2>>"${perf_stderr}" \
        || {
          status="fail"
          reason="${reason:-perf script failed}"
        }
      if [[ -s "${perf_script}" ]] && command -v stackcollapse-perf.pl >/dev/null 2>&1 && command -v flamegraph.pl >/dev/null 2>&1; then
        stackcollapse-perf.pl "${perf_script}" 2>>"${perf_stderr}" | flamegraph.pl >"${perf_flamegraph}" 2>>"${perf_stderr}" \
          || write_unavailable_flamegraph "${perf_flamegraph}" "flamegraph generation failed"
      else
        write_unavailable_flamegraph "${perf_flamegraph}" "flamegraph tooling unavailable"
      fi
    fi
    perf_data_final="$(compress_profile_artifact "${perf_data}")"
    perf_script_final="$(compress_profile_artifact "${perf_script}")"
    cpu_json="$(jq -cn \
      --arg event "${diagnostic_profile_event}" \
      --arg frequency "${diagnostic_profile_frequency}" \
      --arg call_graph "${profile_call_graph}" \
      --arg pids "${pid_csv:-}" \
      --arg perf_data "$(profile_relpath "${perf_data_final}")" \
      --arg perf_report "$(profile_relpath "${perf_report}")" \
      --arg perf_script "$(profile_relpath "${perf_script_final}")" \
      --arg perf_stderr "$(profile_relpath "${perf_stderr}")" \
      --arg flamegraph "$(profile_relpath "${perf_flamegraph}")" \
      --arg metadata "$(profile_relpath "${perf_metadata}")" \
      --arg binary "${copied_binary:+$(profile_relpath "${copied_binary}")}" \
      '{
        enabled: true,
        event: $event,
        frequency: ($frequency | tonumber),
        call_graph: $call_graph,
        host_pids: (if $pids == "" then [] else ($pids | split(",") | map(tonumber)) end),
        artifacts: {
          perf_data: $perf_data,
          perf_report: $perf_report,
          perf_script: $perf_script,
          perf_stderr: $perf_stderr,
          flamegraph: $flamegraph,
          metadata: $metadata,
          binary: (if $binary == "" then null else $binary end)
        }
      }')"
    printf '%s\n' "${cpu_json}" >"${perf_metadata}"
  elif diagnostic_profile_mode_has_cpu; then
    cpu_json="$(jq -cn --arg reason "${reason:-cpu profiling was not started}" '{enabled: true, status: "unavailable", reason: $reason}')"
  fi

  if diagnostic_profile_mode_has_memory; then
    after_json="$(diagnostic_collect_resources_json after)"
    resource_path="${profile_memory_dir}/${profile_name}.resource.json"
    memory_metadata_path="${profile_memory_dir}/${profile_name}.metadata.json"
    heap_dir="${profile_memory_dir}/${profile_name}/heap"
    heap_reason="allocation stack heap profiling is not enabled for ${comparator}; use RSS, FD, task, thread, and smaps evidence from this diagnostic run"
    write_heap_evidence "${comparator}" "${heap_dir}" "${heap_reason}"
    memory_json="$(jq -cn \
      --argjson before "${before_json}" \
      --argjson after "${after_json}" \
      --arg resource "$(profile_relpath "${resource_path}")" \
      --arg metadata "$(profile_relpath "${memory_metadata_path}")" \
      --arg heap_dir "$(profile_relpath "${heap_dir}")" \
      --arg unsupported_heap_reason "${heap_reason}" \
      'def sum_field($rows; $field): [$rows[]? | select(.available == true) | .[$field] // 0] | add // 0;
       {
         enabled: true,
         before: $before,
         after: $after,
         deltas: {
           memory_rss_bytes: (sum_field($after; "memory_rss_bytes") - sum_field($before; "memory_rss_bytes")),
           fd_count: (sum_field($after; "fd_count") - sum_field($before; "fd_count")),
           task_count: (sum_field($after; "task_count") - sum_field($before; "task_count")),
           thread_count: (sum_field($after; "thread_count") - sum_field($before; "thread_count"))
         },
         artifacts: {
           resource: $resource,
           metadata: $metadata,
           heap_dir: $heap_dir
         },
         unsupported_heap_reason: $unsupported_heap_reason
       }')"
    printf '%s\n' "${memory_json}" >"${resource_path}"
    printf '%s\n' "${memory_json}" >"${memory_metadata_path}"
  fi

  finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  append_profile_result "$(jq -cn \
    --arg label "${label}" \
    --arg comparator "${comparator}" \
    --arg protocol "${protocol}" \
    --arg mode "${diagnostic_profile_mode}" \
    --arg status "${status}" \
    --arg reason "${reason}" \
    --arg gate_mode "${diagnostic_profile_gate_mode}" \
    --arg started_at "${started_at}" \
    --arg finished_at "${finished_at}" \
    --arg duration_seconds "${duration}" \
    --arg warmup_seconds "${warmup_seconds}" \
    --arg profile_seconds "${profile_seconds}" \
    --argjson replay_exit_code "${replay_status}" \
    --argjson cpu "${cpu_json}" \
    --argjson memory "${memory_json}" \
    '{
      schema_version: 1,
      label: $label,
      comparator: $comparator,
      scenario: $label,
      protocol: $protocol,
      profile_mode: $mode,
      status: $status,
      gate_mode: $gate_mode,
      reason: (if $reason == "" then null else $reason end),
      started_at: $started_at,
      finished_at: $finished_at,
      load_duration_seconds: ($duration_seconds | tonumber),
      warmup_seconds: ($warmup_seconds | tonumber),
      profile_seconds: ($profile_seconds | tonumber),
      replay_exit_code: $replay_exit_code,
      cpu: $cpu,
      memory: $memory
    }')"

  if [[ "${status}" != "pass" ]]; then
    handle_diagnostic_profile_failure "diagnostic profiling failed for ${label}: ${reason:-unknown failure}"
  fi
}

run_profiled_probe_json() {
  local label="$1"
  local duration="$2"
  shift 2

  local profile_name pid profile_seconds profile_binary buildid_dir
  local perf_data perf_report perf_script perf_stderr metadata_json
  local started_at finished_at json probe_status perf_pid perf_status
  profile_name="$(profile_artifact_name "${label}")"
  pid="$(active_oxibelt_host_pid "${label}")"
  profile_seconds="$(profile_duration_seconds "${duration}")"
  profile_binary="${profiles_dir}/${profile_name}.oxibelt"
  buildid_dir="${profiles_dir}/.build-id"
  perf_data="${profiles_dir}/${profile_name}.perf.data"
  perf_report="${profiles_dir}/${profile_name}.perf.report.txt"
  perf_script="${profiles_dir}/${profile_name}.perf.script.txt"
  perf_stderr="${profiles_dir}/${profile_name}.perf.stderr.log"
  metadata_json="${profiles_dir}/${profile_name}.metadata.json"
  mkdir -p "${profiles_dir}" "${buildid_dir}"

  if ! docker cp "${active_proxy_container}:/usr/local/bin/oxibelt" "${profile_binary}" >>"${perf_stderr}" 2>&1; then
    fail_with_diagnostics "failed to copy OxiBelt binary for profiling label ${label}"
  fi
  chmod 0644 "${profile_binary}" || true
  PERF_BUILDID_DIR="${buildid_dir}" perf buildid-cache --add "${profile_binary}" >>"${perf_stderr}" 2>&1 || true

  started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  perf record \
    --freq "${profile_frequency}" \
    --call-graph "${profile_call_graph}" \
    --pid "${pid}" \
    --output "${perf_data}" \
    -- sleep "${profile_seconds}" >>"${perf_stderr}" 2>&1 &
  perf_pid=$!
  sleep 0.2

  probe_status=0
  json="$(run_probe_json "$@")" || probe_status=$?

  perf_status=0
  if kill -0 "${perf_pid}" >/dev/null 2>&1; then
    kill -INT "${perf_pid}" >/dev/null 2>&1 || true
  fi
  wait "${perf_pid}" || perf_status=$?
  finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  if [[ "${probe_status}" != "0" ]]; then
    printf '%s\n' "${json}"
    return "${probe_status}"
  fi
  if [[ "${perf_status}" != "0" && "${perf_status}" != "130" && "${perf_status}" != "143" ]]; then
    fail_with_diagnostics "perf record failed for profiling label ${label}; see profiles/${profile_name}.perf.stderr.log"
  fi
  if [[ ! -s "${perf_data}" ]]; then
    fail_with_diagnostics "perf record produced no data for profiling label ${label}"
  fi

  PERF_BUILDID_DIR="${buildid_dir}" perf report --stdio --input "${perf_data}" >"${perf_report}" 2>>"${perf_stderr}" \
    || fail_with_diagnostics "perf report failed for profiling label ${label}; see profiles/${profile_name}.perf.stderr.log"
  PERF_BUILDID_DIR="${buildid_dir}" perf script --input "${perf_data}" >"${perf_script}" 2>>"${perf_stderr}" \
    || fail_with_diagnostics "perf script failed for profiling label ${label}; see profiles/${profile_name}.perf.stderr.log"
  jq -n \
    --arg label "${label}" \
    --arg container "${active_proxy_container}" \
    --argjson host_pid "${pid}" \
    --arg frequency "${profile_frequency}" \
    --arg call_graph "${profile_call_graph}" \
    --arg duration_seconds "${duration}" \
    --arg warmup_seconds "${warmup_seconds}" \
    --arg profile_seconds "${profile_seconds}" \
    --arg started_at "${started_at}" \
    --arg finished_at "${finished_at}" \
    --arg perf_data "profiles/${profile_name}.perf.data" \
    --arg perf_report "profiles/${profile_name}.perf.report.txt" \
    --arg perf_script "profiles/${profile_name}.perf.script.txt" \
    --arg perf_stderr "profiles/${profile_name}.perf.stderr.log" \
    --arg oxibelt_binary "profiles/${profile_name}.oxibelt" \
    '{
      schema_version: 1,
      label: $label,
      container: $container,
      host_pid: $host_pid,
      frequency: ($frequency | tonumber),
      call_graph: $call_graph,
      load_duration_seconds: ($duration_seconds | tonumber),
      warmup_seconds: ($warmup_seconds | tonumber),
      profile_seconds: ($profile_seconds | tonumber),
      started_at: $started_at,
      finished_at: $finished_at,
      artifacts: {
        perf_data: $perf_data,
        perf_report: $perf_report,
        perf_script: $perf_script,
        perf_stderr: $perf_stderr,
        oxibelt_binary: $oxibelt_binary
      }
    }' >"${metadata_json}"

  printf '%s\n' "${json}"
}

run_probe_json() {
  local probe_container="oxibelt-perf-probe-${run_id}-${RANDOM}"
  local output container_logs selected_output status json probe_label previous_arg probe_log_name probe_log_path arg
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
  container_logs="$(docker logs "${probe_container}" 2>&1 || true)"
  selected_output="${output}"
  if [[ "${status}" == "0" ]]; then
    json="$(printf '%s\n' "${selected_output}" | tail -n 1)"
    if ! jq -e . >/dev/null <<<"${json}" && [[ -n "${container_logs}" ]]; then
      selected_output="${container_logs}"
      json="$(printf '%s\n' "${selected_output}" | tail -n 1)"
    fi
  fi
  {
    printf 'Command: perf-probe'
    printf ' %q' "$@"
    printf '\n\n'
    printf 'Exit status: %s\n\n' "${status}"
    printf 'Attached output:\n'
    printf '%s\n' "${output}"
    printf '\nContainer logs:\n'
    printf '%s\n' "${container_logs}"
  } >"${probe_log_path}"
  docker rm -f "${probe_container}" >/dev/null 2>&1 || true
  if [[ "${status}" != "0" ]]; then
    if [[ -n "${output}" ]]; then
      echo "${output}" >&2
    else
      echo "${container_logs}" >&2
    fi
    return "${status}"
  fi
  if ! jq -e . >/dev/null <<<"${json}"; then
    echo "${selected_output}" >&2
    return 1
  fi
  printf '%s\n' "${json}"
}

start_perf_upstreams() {
  docker run -d \
    --name "perf-upstream-${run_id}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias perf-upstream \
    "${perf_probe_image}" \
    upstream \
    --listen 0.0.0.0:18080 \
    --name perf-upstream \
    --protocol h1 >/dev/null

  docker run -d \
    --name "perf-upstream-h2c-${run_id}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias perf-upstream-h2c \
    "${perf_probe_image}" \
    upstream \
    --listen 0.0.0.0:18082 \
    --name perf-upstream-h2c \
    --protocol h2c >/dev/null

  local h2_container="perf-upstream-h2-${run_id}"
  docker create \
    --name "${h2_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias perf-upstream-h2 \
    "${perf_probe_image}" \
    upstream \
    --listen 0.0.0.0:18444 \
    --name perf-upstream-h2 \
    --protocol h2 \
    --cert /tls/fullchain.pem \
    --key /tls/privkey.pem >/dev/null
  docker cp "${tls_dir}/." "${h2_container}:/tls"
  docker start "${h2_container}" >/dev/null
}

append_result() {
  local json="$1"
  json="$(jq -c --arg target "${amd64_target_cpu}" '. + {amd64_target_cpu: $target}' <<<"${json}")"
  printf '%s\n' "${json}" >>"${results_jsonl}"
  local label type protocol skipped requests rps p95 p99 errors fast_path_hit_rate direct_h1_hit_rate direct_h2_hit_rate direct_h1_pool_events static_sources result_text fast_path_protocol
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
  result_text="$(printf '%s req, %.2f/sec, p95 %.2f ms, p99 %.2f ms' "${requests}" "${rps}" "${p95}" "${p99}")"
  for fast_path_protocol in h1 h2 h3; do
    fast_path_hit_rate="$(jq -r --arg protocol "${fast_path_protocol}" '.fast_path.plain_proxy[$protocol].hit_rate // empty' <<<"${json}")"
    if [[ -n "${fast_path_hit_rate}" ]]; then
      result_text="${result_text}, ${fast_path_protocol} fast-path $(jq -n -r --argjson rate "${fast_path_hit_rate}" '($rate * 100.0 | tostring) + "%"')"
    fi
    direct_h1_hit_rate="$(jq -r --arg protocol "${fast_path_protocol}" '.fast_path.transport.direct_h1[$protocol].hit_rate // empty' <<<"${json}")"
    if [[ -n "${direct_h1_hit_rate}" ]]; then
      result_text="${result_text}, direct h1 ${fast_path_protocol} $(jq -n -r --argjson rate "${direct_h1_hit_rate}" '($rate * 100.0 | tostring) + "%"')"
    fi
    direct_h2_hit_rate="$(jq -r --arg protocol "${fast_path_protocol}" '.fast_path.transport.direct_h2[$protocol].hit_rate // empty' <<<"${json}")"
    if [[ -n "${direct_h2_hit_rate}" ]]; then
      result_text="${result_text}, direct h2 ${fast_path_protocol} $(jq -n -r --argjson rate "${direct_h2_hit_rate}" '($rate * 100.0 | tostring) + "%"')"
    fi
  done
  static_sources="$(jq -r '.fast_path.static_responses // {} | to_entries | map(.key + " served=" + ((.value.served // 0) | tostring)) | join(", ")' <<<"${json}")"
  if [[ -n "${static_sources}" ]]; then
    result_text="${result_text}, static ${static_sources}"
  fi
  direct_h1_pool_events="$(jq -r '.fast_path.pool.direct_h1 // {} | to_entries | map(.key + "=" + (.value | tostring)) | join(", ")' <<<"${json}")"
  if [[ -n "${direct_h1_pool_events}" ]]; then
    result_text="${result_text}, direct h1 pool ${direct_h1_pool_events}"
  fi
  printf '| `%s` | `%s` | `%s` | %s | errors=%s |\n' \
    "${label}" "${type}" "${protocol}" "${result_text}" "${errors}" >>"${summary_md}"
}

result_failure_reason() {
  local json="$1"
  local type skipped errors requests p99 label
  label="$(jq -r '.label // "unknown"' <<<"${json}")"
  skipped="$(jq -r '.skipped // false' <<<"${json}")"
  [[ "${skipped}" == "true" ]] && return 1

  type="$(jq -r '.type // "unknown"' <<<"${json}")"
  errors="$(jq -r '.errors // 0' <<<"${json}")"
  requests="$(jq -r '.requests // .handshakes // 0' <<<"${json}")"
  p99="$(jq -r '.p99_ms // 0' <<<"${json}")"

  if [[ "${requests}" == "0" ]]; then
    printf 'performance probe produced zero requests: %s\n' "${label}"
    return 0
  fi

  if [[ "${type}" != "stress" && "${errors}" != "0" ]]; then
    if [[ "${type}" != "load" ]] || ! load_errors_within_budget "${errors}" "${requests}"; then
      printf 'performance probe reported request errors: %s\n' "${label}"
      return 0
    fi
  fi

  if [[ "${type}" == "stress" ]]; then
    local connections
    connections="$(jq -r '.connections // 0' <<<"${json}")"
    if [[ "${connections}" != "0" && "${errors}" == "${connections}" ]]; then
      printf 'stress probe could not establish any useful connections: %s\n' "${label}"
      return 0
    fi
    return 1
  fi

  if jq -e --argjson max "${max_p99_ms}" '(.p99_ms // 0) > $max' >/dev/null <<<"${json}"; then
    printf 'performance probe exceeded p99 sanity ceiling (%sms > %sms): %s\n' \
      "${p99}" "${max_p99_ms}" "${label}"
    return 0
  fi

  return 1
}

normalize_diagnostic_comparator_result() {
  local json="$1"
  local label reason
  label="$(jq -r '.label // "unknown"' <<<"${json}")"
  if ! diagnostic_comparator_label "${label}"; then
    printf '%s\n' "${json}"
    return
  fi
  if ! reason="$(result_failure_reason "${json}")"; then
    printf '%s\n' "${json}"
    return
  fi
  jq -c --arg reason "${reason}" \
    '. + {
      skipped: true,
      diagnostic: true,
      diagnostic_status: "fail",
      reason: $reason
    }' <<<"${json}"
}

direct_h2_diagnostic_load_label() {
  local label="$1"
  local protocol="$2"
  local host="$3"
  if [[ "${host}" != "oxibelt" ]]; then
    return 1
  fi
  case "${label}:${protocol}" in
    oxibelt-h2-upstream-h2c:h2|oxibelt-h2-upstream-h2:h2|oxibelt-h3-upstream-h2c:h3|oxibelt-h3-upstream-h2:h3) return 0 ;;
    *) return 1 ;;
  esac
}

metrics_mode_diagnostic_load_label() {
  local label="$1"
  local protocol="$2"
  local host="$3"
  if [[ "${host}" != "oxibelt" ]]; then
    return 1
  fi
  case "${label}:${protocol}" in
    oxibelt-metrics-*-h2:h2|oxibelt-metrics-*-h3:h3) return 0 ;;
    *) return 1 ;;
  esac
}

h3_inline_diagnostic_load_label() {
  local label="$1"
  local protocol="$2"
  local host="$3"
  [[ "${host}" == "oxibelt" && "${label}:${protocol}" == "oxibelt-h3-inline-fast-path-experiment:h3" ]]
}

diagnostic_load_label() {
  direct_h2_diagnostic_load_label "$@" \
    || metrics_mode_diagnostic_load_label "$@" \
    || h3_inline_diagnostic_load_label "$@"
}

normalize_diagnostic_load_result() {
  local json="$1"
  local label protocol host reason
  label="$(jq -r '.label // "unknown"' <<<"${json}")"
  protocol="$(jq -r '.protocol // empty' <<<"${json}")"
  host="$(diagnostic_profile_comparator_from_label "${label}")"
  if ! diagnostic_load_label "${label}" "${protocol}" "${host}"; then
    printf '%s\n' "${json}"
    return
  fi
  if reason="$(result_failure_reason "${json}")"; then
    jq -c --arg reason "${reason}" \
      '. + {diagnostic: true, diagnostic_status: "fail", reason: $reason}' <<<"${json}"
  else
    jq -c '. + {diagnostic: true, diagnostic_status: "pass"}' <<<"${json}"
  fi
}

assert_result() {
  local json="$1"
  local reason
  if reason="$(result_failure_reason "${json}")"; then
    fail_with_diagnostics "${reason}"
  fi
}

assert_diagnostic_result() {
  local json="$1"
  local requests skipped
  skipped="$(jq -r '.skipped // false' <<<"${json}")"
  [[ "${skipped}" == "true" ]] && return
  requests="$(jq -r '.requests // .handshakes // 0' <<<"${json}")"
  if [[ "${requests}" == "0" ]]; then
    fail_with_diagnostics "diagnostic performance probe produced zero requests: $(jq -r '.label' <<<"${json}")"
  fi
}

external_artifact_name() {
  local name="$1"
  name="${name//[^A-Za-z0-9_.-]/_}"
  if [[ -z "${name}" ]]; then
    echo external
  else
    echo "${name}"
  fi
}

append_external_result() {
  local json="$1"
  json="$(jq -c --arg target "${amd64_target_cpu}" '. + {amd64_target_cpu: $target}' <<<"${json}")"
  printf '%s\n' "${json}" >>"${external_results_jsonl}"

  if [[ "${external_summary_started}" != "1" ]]; then
    {
      echo
      echo "External benchmarks:"
      echo
      echo "| Tool | Scenario | Comparator | Protocol | Status | Result | Notes |"
      echo "| --- | --- | --- | --- | --- | --- | --- |"
    } >>"${summary_md}"
    external_summary_started=1
  fi

  local tool scenario comparator protocol status rps p99 error_rate reason
  tool="$(jq -r '.tool // "unknown"' <<<"${json}")"
  scenario="$(jq -r '.scenario // "unknown"' <<<"${json}")"
  comparator="$(jq -r '.comparator // "unknown"' <<<"${json}")"
  protocol="$(jq -r '.protocol // "-"' <<<"${json}")"
  status="$(jq -r '.status // "unknown"' <<<"${json}")"
  rps="$(jq -r 'if .rps == null then "-" else (.rps | tostring) end' <<<"${json}")"
  p99="$(jq -r 'if .p99_ms == null then "-" else (.p99_ms | tostring) end' <<<"${json}")"
  error_rate="$(jq -r 'if .error_rate == null then "-" else (.error_rate | tostring) end' <<<"${json}")"
  reason="$(jq -r '.reason // "-"' <<<"${json}")"
  printf '| `%s` | `%s` | `%s` | `%s` | `%s` | rps=%s, p99_ms=%s, error_rate=%s | %s |\n' \
    "${tool}" "${scenario}" "${comparator}" "${protocol}" "${status}" "${rps}" "${p99}" "${error_rate}" "${reason}" >>"${summary_md}"
}

external_result_json() {
  local label="$1"
  local tool="$2"
  local comparator="$3"
  local scenario="$4"
  local protocol="$5"
  local status="$6"
  local output_file="$7"
  local exit_code="$8"
  local reason="$9"
  local rps="${10}"
  local p95="${11}"
  local p99="${12}"
  local error_rate="${13}"
  local requests="${14}"
  jq -cn \
    --arg label "${label}" \
    --arg tool "${tool}" \
    --arg comparator "${comparator}" \
    --arg scenario "${scenario}" \
    --arg protocol "${protocol}" \
    --arg status "${status}" \
    --arg output_file "${output_file}" \
    --arg reason "${reason}" \
    --arg rps "${rps}" \
    --arg p95 "${p95}" \
    --arg p99 "${p99}" \
    --arg error_rate "${error_rate}" \
    --arg requests "${requests}" \
    --arg gate_mode "${external_benchmark_gate_mode}" \
    --argjson exit_code "${exit_code}" \
    'def maybe_number($value): if $value == "" then null else ($value | tonumber) end;
     {
       schema_version: 1,
       label: $label,
       tool: $tool,
       comparator: $comparator,
       scenario: $scenario,
       protocol: $protocol,
       status: $status,
       gate_mode: $gate_mode,
       output_file: $output_file,
       exit_code: $exit_code,
       reason: (if $reason == "" then null else $reason end),
       rps: maybe_number($rps),
       p95_ms: maybe_number($p95),
       p99_ms: maybe_number($p99),
       error_rate: maybe_number($error_rate),
       requests: maybe_number($requests)
     }'
}

run_external_container() {
  local output_path="$1"
  local command="$2"
  local container="oxibelt-external-benchmark-${run_id}-${RANDOM}"
  local output status start_output wait_output
  docker create \
    --name "${container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    "${external_benchmark_image}" \
    sh -c "${command}" >/dev/null
  docker cp "${tls_dir}/fullchain.pem" "${container}:/tls/proxy-ca.pem"

  status=0
  start_output="$(docker start "${container}" 2>&1 >/dev/null)" || status=$?
  if [[ "${status}" != "0" ]]; then
    output="${start_output}"
  else
    wait_output="$(docker wait "${container}" 2>&1)" || status=$?
    if [[ "${status}" != "0" ]]; then
      output="${wait_output}"
    elif [[ "${wait_output}" =~ ^[0-9]+$ ]]; then
      status="${wait_output}"
      output="$(docker logs "${container}" 2>&1 || true)"
    else
      status=1
      output="${wait_output}"
    fi
  fi
  printf '%s\n' "${output}" >"${output_path}"
  docker rm -f "${container}" >/dev/null 2>&1 || true
  return "${status}"
}

record_external_skip() {
  local label="$1"
  local tool="$2"
  local comparator="$3"
  local scenario="$4"
  local protocol="$5"
  local output_file="$6"
  local reason="$7"
  local json
  json="$(external_result_json "${label}" "${tool}" "${comparator}" "${scenario}" "${protocol}" skipped "${output_file}" 0 "${reason}" "" "" "" "" "")"
  append_external_result "${json}"
}

run_external_h2load() {
  local comparator="$1"
  local host="$2"
  local scenario="$3"
  local protocol="$4"
  local label="${comparator}-external-h2load-${scenario}"
  local artifact_name output_path output_file command status reason rps requests json row_status
  artifact_name="$(external_artifact_name "${label}")"
  output_path="${external_h2load_dir}/${artifact_name}.txt"
  output_file="external-h2load/${artifact_name}.txt"
  if [[ "${protocol}" == "h3" ]]; then
    command="cp /tls/proxy-ca.pem /usr/local/share/ca-certificates/oxibelt-proxy.crt && update-ca-certificates >/dev/null && exec h2load -D ${duration_seconds}s --warm-up-time=${warmup_seconds}s -c ${concurrency} -m 16 --h3 --no-udp-gso --connect-to ${host}:8443 --sni proxy -H ':authority: example.test' 'https://proxy:8443/perf/h3?body=ok'"
  else
    command="cp /tls/proxy-ca.pem /usr/local/share/ca-certificates/oxibelt-proxy.crt && update-ca-certificates >/dev/null && exec h2load -D ${duration_seconds}s --warm-up-time=${warmup_seconds}s -c ${concurrency} -m 16 --alpn-list h2 --connect-to ${host}:8443 --sni proxy -H ':authority: example.test' 'https://proxy:8443/perf/h2?body=ok'"
  fi

  status=0
  run_external_container "${output_path}" "${command}" || status=$?
  rps="$(sed -n 's/^finished in .*, \([0-9.][0-9.]*\) req\/s.*/\1/p' "${output_path}" | tail -n 1)"
  requests="$(sed -n 's/^requests: .* \([0-9][0-9]*\) done.*/\1/p' "${output_path}" | tail -n 1)"
  reason=""
  row_status=pass
  if [[ "${status}" != "0" ]]; then
    reason="h2load exited with status ${status}"
    row_status=fail
  elif [[ -z "${requests}" || "${requests}" == "0" ]]; then
    status=1
    reason="h2load produced no completed requests"
    row_status=fail
  fi
  json="$(external_result_json "${label}" h2load "${comparator}" "${scenario}" "${protocol}" "${row_status}" "${output_file}" "${status}" "${reason}" "${rps}" "" "" "" "${requests}")"
  append_external_result "${json}"
  if [[ "${status}" != "0" ]]; then
    # Aggregation classifies h2load H3 zero-completion rows after all comparators run.
    if [[ "${protocol}" == "h3" && "${reason}" == "h2load produced no completed requests" ]]; then
      external_h2load_h3_zero_deferred=1
      return
    fi
    handle_external_benchmark_failure "h2load ${protocol} external benchmark failed for ${comparator}: ${reason}"
  fi
}

run_external_oha() {
  local comparator="$1"
  local host="$2"
  local label="${comparator}-external-oha-h2-fixed-qps"
  local artifact_name output_path output_file command status json_valid p99_ms error_rate rps requests reason json row_status
  artifact_name="$(external_artifact_name "${label}")"
  output_path="${external_oha_dir}/${artifact_name}.json"
  output_file="external-oha/${artifact_name}.json"
  command="exec oha -z ${duration_seconds}s -c ${concurrency} -q ${external_oha_qps} --http-version 2 --cacert /tls/proxy-ca.pem --host example.test --connect-to example.test:8443:${host}:8443 --latency-correction --no-tui --disable-color --output-format json 'https://example.test:8443/perf/h2?body=ok'"

  status=0
  run_external_container "${output_path}" "${command}" || status=$?
  json_valid=1
  jq -e . >/dev/null <"${output_path}" || json_valid=0
  reason=""
  p99_ms=""
  error_rate=""
  rps=""
  requests=""
  row_status=pass
  if [[ "${json_valid}" == "1" ]]; then
    p99_ms="$(jq -r '((.latencyPercentiles.p99 // null) * 1000) // empty' "${output_path}")"
    error_rate="$(jq -r '1 - (.summary.successRate // 0)' "${output_path}")"
    rps="$(jq -r '.summary.requestsPerSec // empty' "${output_path}")"
    requests="$(jq -r '[.statusCodeDistribution[]?, .errorDistribution[]?] | add // empty' "${output_path}")"
    if [[ "${status}" == "0" ]] && jq -n -e --argjson p99 "${p99_ms:-0}" --argjson max "${external_oha_max_p99_ms}" '$p99 > $max' >/dev/null; then
      status=1
      reason="oha p99 ${p99_ms}ms exceeded ${external_oha_max_p99_ms}ms"
    fi
    if [[ "${status}" == "0" ]] && jq -n -e --argjson observed_error_rate "${error_rate:-1}" --argjson max "${external_oha_max_error_rate}" '$observed_error_rate > $max' >/dev/null; then
      status=1
      reason="oha error rate ${error_rate} exceeded ${external_oha_max_error_rate}"
    fi
  else
    reason="oha output was not valid JSON"
  fi
  if [[ "${status}" != "0" && -z "${reason}" ]]; then
    reason="oha exited with status ${status}"
  fi
  if [[ "${status}" != "0" || "${json_valid}" != "1" ]]; then
    row_status=fail
  fi
  json="$(external_result_json "${label}" oha "${comparator}" fixed-qps-h2 h2 "${row_status}" "${output_file}" "${status}" "${reason}" "${rps}" "" "${p99_ms}" "${error_rate}" "${requests}")"
  append_external_result "${json}"
  if [[ "${status}" != "0" || "${json_valid}" != "1" ]]; then
    handle_external_benchmark_failure "oha fixed-QPS external benchmark failed for ${comparator}: ${reason}"
  fi
}

run_external_wrk() {
  local comparator="$1"
  local host="$2"
  local label="${comparator}-external-wrk-h1-keepalive"
  local artifact_name output_path output_file command status reason rps requests p99 json row_status
  artifact_name="$(external_artifact_name "${label}")"
  output_path="${external_wrk_dir}/${artifact_name}.txt"
  output_file="external-wrk/${artifact_name}.txt"
  command="exec wrk -t2 -c ${concurrency} -d ${duration_seconds}s -H 'Host: example.test' 'http://${host}:8080/perf/h1?body=ok'"

  status=0
  run_external_container "${output_path}" "${command}" || status=$?
  rps="$(sed -n 's/^Requests\/sec:[[:space:]]*\([0-9.][0-9.]*\).*/\1/p' "${output_path}" | tail -n 1)"
  requests="$(sed -n 's/^[[:space:]]*\([0-9][0-9]*\) requests in .*/\1/p' "${output_path}" | tail -n 1)"
  p99="$(sed -n 's/^[[:space:]]*99%[[:space:]]*\([0-9.][0-9.]*\)ms.*/\1/p' "${output_path}" | tail -n 1)"
  reason=""
  row_status=pass
  if [[ "${status}" != "0" ]]; then
    reason="wrk exited with status ${status}"
    row_status=fail
  elif [[ -z "${rps}" || "${rps}" == "0" ]]; then
    status=1
    reason="wrk produced no positive Requests/sec value"
    row_status=fail
  fi
  json="$(external_result_json "${label}" wrk "${comparator}" h1-keepalive h1 "${row_status}" "${output_file}" "${status}" "${reason}" "${rps}" "" "${p99}" "" "${requests}")"
  append_external_result "${json}"
  if [[ "${status}" != "0" ]]; then
    handle_external_benchmark_failure "wrk HTTP/1.1 external benchmark failed for ${comparator}: ${reason}"
  fi
}

run_external_benchmarks_for_comparator() {
  local comparator="$1"
  local host="$2"
  local h3_mode="$3"
  local h3_label h3_output_file
  if [[ "${external_benchmarks}" != "1" ]]; then
    return
  fi

  if has_external_tool h2load; then
    run_external_h2load "${comparator}" "${host}" h2 h2
    case "${h3_mode}" in
      required)
        run_external_h2load "${comparator}" "${host}" h3 h3
        ;;
      optional)
        if h3_probe_succeeds "${host}"; then
          run_external_h2load "${comparator}" "${host}" h3 h3
        else
          h3_label="${comparator}-external-h2load-h3"
          h3_output_file="external-h2load/$(external_artifact_name "${h3_label}").txt"
          record_external_skip "${h3_label}" h2load "${comparator}" h3 h3 "${h3_output_file}" "HTTP/3 is not available for this comparator image"
        fi
        ;;
      disabled)
        h3_label="${comparator}-external-h2load-h3"
        h3_output_file="external-h2load/$(external_artifact_name "${h3_label}").txt"
        record_external_skip "${h3_label}" h2load "${comparator}" h3 h3 "${h3_output_file}" "HTTP/3 is not available for this comparator image"
        ;;
      *)
        handle_external_benchmark_failure "invalid HTTP/3 external benchmark mode for ${comparator}: ${h3_mode}"
        ;;
    esac
  fi

  if has_external_tool oha; then
    run_external_oha "${comparator}" "${host}"
  fi

  if has_external_tool wrk; then
    run_external_wrk "${comparator}" "${host}"
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
    handle_regression_gate_violation "OxiBelt static-16k-h1c regression gate failed: ratio ${ratio} < ${static_16k_h1c_min_caddy_ratio} vs Caddy (${oxibelt_rps} RPS vs ${caddy_rps} RPS)"
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
    handle_regression_gate_violation "OxiBelt WAF enforcing regression gate failed: RPS ${waf_enforcing_rps} < ${waf_enforcing_min_rps}"
  fi
  if jq -n -e --argjson rps "${crs_enforcing_rps}" --argjson min "${crs_enforcing_min_rps}" '$rps < $min' >/dev/null; then
    handle_regression_gate_violation "OxiBelt CRS enforcing regression gate failed: RPS ${crs_enforcing_rps} < ${crs_enforcing_min_rps}"
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
    handle_regression_gate_violation "OxiBelt WAF p99 regression gate failed: enforcing/monitor ratio ${waf_p99_ratio} > ${waf_crs_max_enforce_p99_ratio} (${waf_enforcing_p99}ms vs ${waf_monitor_p99}ms)"
  fi
  if jq -n -e --argjson ratio "${crs_p99_ratio}" --argjson max "${waf_crs_max_enforce_p99_ratio}" '$ratio > $max' >/dev/null; then
    handle_regression_gate_violation "OxiBelt CRS p99 regression gate failed: enforcing/monitor ratio ${crs_p99_ratio} > ${waf_crs_max_enforce_p99_ratio} (${crs_enforcing_p99}ms vs ${crs_monitor_p99}ms)"
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

record_diagnostic_comparator_skip() {
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
    '{
      label: $label,
      type: $type,
      protocol: $protocol,
      skipped: true,
      diagnostic: true,
      diagnostic_status: "fail",
      reason: $reason
    }')"
  append_result "${json}"
}

record_diagnostic_load_skip() {
  record_diagnostic_comparator_skip "$@"
}

run_load() {
  local label="$1"
  local protocol="$2"
  local host="$3"
  local path="$4"
  local duration="$5"
  local conc="$6"
  shift 6
  local extra_args=("$@")
  local port="8443"
  local json fast_path_protocol direct_transport fast_path_before fast_path_after fast_path_delta request_body_before request_body_after request_body_delta direct_h1_before direct_h1_after direct_h1_delta direct_h2_before direct_h2_after direct_h2_delta direct_h1_pool_before direct_h1_pool_after direct_h1_pool_delta direct_h2_pool_before direct_h2_pool_after direct_h2_pool_delta direct_h1_io_backend_before direct_h1_io_backend_after direct_h1_io_backend_delta_json stage_timing_before stage_timing_after stage_timing_delta_json static_fast_path_before static_fast_path_after static_fast_path_delta
  if [[ "${protocol}" == "h1c" ]]; then
    port="8080"
  fi
  fast_path_protocol="$(plain_proxy_fast_path_gate_protocol "${label}" "${protocol}" "${host}")"
  direct_transport="$(direct_transport_gate_transport "${label}" "${protocol}" "${host}")"
  if [[ -n "${fast_path_protocol}" ]]; then
    fast_path_before="$(plain_proxy_fast_path_metrics "${host}" "${label}-fast-path-before" "${fast_path_protocol}")"
    request_body_before="$(fast_path_request_body_metrics "${host}" "${label}-request-body-before" "${fast_path_protocol}")"
    direct_h1_before="$(direct_h1_transport_metrics "${host}" "${label}-direct-h1-before" "${fast_path_protocol}")"
    direct_h2_before="$(direct_h2_transport_metrics "${host}" "${label}-direct-h2-before" "${fast_path_protocol}")"
    direct_h1_pool_before="$(direct_h1_pool_metrics "${host}" "${label}-direct-h1-pool-before")"
    direct_h1_io_backend_before="$(direct_h1_io_backend_metrics "${host}" "${label}-direct-h1-io-before")"
    if [[ "${direct_transport}" == "direct_h2" ]]; then
      direct_h2_pool_before="$(direct_h2_pool_metrics "${host}" "${label}-direct-h2-pool-before")"
    fi
    stage_timing_before="$(fast_path_stage_timing_metrics "${host}" "${label}-stage-timing-before")"
  fi
  if static_fast_path_gate_label "${label}" "${protocol}" "${host}"; then
    static_fast_path_before="$(static_fast_path_metrics "${host}" "${label}-static-fast-path-before")"
  fi
  local -a probe_args=(
    load
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
    --expect-status 200 \
    "${extra_args[@]}"
  )
  if should_profile_load "${label}"; then
    if ! json="$(run_profiled_probe_json "${label}" "${duration}" "${probe_args[@]}")"; then
      if diagnostic_comparator_label "${label}"; then
        record_diagnostic_comparator_skip "${label}" load "${protocol}" "diagnostic comparator probe failed before producing a valid result"
        sample_stats "${label}"
        return
      elif diagnostic_load_label "${label}" "${protocol}" "${host}"; then
        record_diagnostic_load_skip "${label}" load "${protocol}" "diagnostic probe failed before producing a valid result"
        sample_stats "${label}"
        return
      fi
      fail_with_diagnostics "performance probe failed before producing a valid result: ${label}"
    fi
  else
    if ! json="$(run_probe_json "${probe_args[@]}")"; then
      if diagnostic_comparator_label "${label}"; then
        record_diagnostic_comparator_skip "${label}" load "${protocol}" "diagnostic comparator probe failed before producing a valid result"
        sample_stats "${label}"
        return
      elif diagnostic_load_label "${label}" "${protocol}" "${host}"; then
        record_diagnostic_load_skip "${label}" load "${protocol}" "diagnostic probe failed before producing a valid result"
        sample_stats "${label}"
        return
      fi
      fail_with_diagnostics "performance probe failed before producing a valid result: ${label}"
    fi
  fi
  if [[ -n "${fast_path_protocol}" ]]; then
    fast_path_after="$(plain_proxy_fast_path_metrics "${host}" "${label}-fast-path-after" "${fast_path_protocol}")"
    request_body_after="$(fast_path_request_body_metrics "${host}" "${label}-request-body-after" "${fast_path_protocol}")"
    direct_h1_after="$(direct_h1_transport_metrics "${host}" "${label}-direct-h1-after" "${fast_path_protocol}")"
    direct_h2_after="$(direct_h2_transport_metrics "${host}" "${label}-direct-h2-after" "${fast_path_protocol}")"
    direct_h1_pool_after="$(direct_h1_pool_metrics "${host}" "${label}-direct-h1-pool-after")"
    direct_h1_io_backend_after="$(direct_h1_io_backend_metrics "${host}" "${label}-direct-h1-io-after")"
    if [[ "${direct_transport}" == "direct_h2" ]]; then
      direct_h2_pool_after="$(direct_h2_pool_metrics "${host}" "${label}-direct-h2-pool-after")"
    fi
    stage_timing_after="$(fast_path_stage_timing_metrics "${host}" "${label}-stage-timing-after")"
    fast_path_delta="$(plain_proxy_fast_path_delta "${fast_path_before}" "${fast_path_after}")"
    request_body_delta="$(counter_map_delta "${request_body_before}" "${request_body_after}")"
    direct_h1_delta="$(direct_h1_transport_delta "${direct_h1_before}" "${direct_h1_after}")"
    direct_h2_delta="$(direct_h2_transport_delta "${direct_h2_before}" "${direct_h2_after}")"
    direct_h1_pool_delta="$(counter_map_delta "${direct_h1_pool_before}" "${direct_h1_pool_after}")"
    direct_h1_pool_delta="$(nonzero_counter_map "${direct_h1_pool_delta}")"
    direct_h1_io_backend_delta_json="$(nested_counter_map_delta "${direct_h1_io_backend_before}" "${direct_h1_io_backend_after}")"
    direct_h1_io_backend_delta_json="$(nonzero_nested_counter_map "${direct_h1_io_backend_delta_json}")"
    if [[ "${direct_transport}" == "direct_h2" ]]; then
      direct_h2_pool_delta="$(counter_map_delta "${direct_h2_pool_before}" "${direct_h2_pool_after}")"
      direct_h2_pool_delta="$(nonzero_counter_map "${direct_h2_pool_delta}")"
    fi
    stage_timing_delta_json="$(stage_timing_delta "${stage_timing_before}" "${stage_timing_after}")"
    json="$(jq -c --arg protocol "${fast_path_protocol}" --argjson fast_path "${fast_path_delta}" --argjson request_body "${request_body_delta}" --argjson direct_h1 "${direct_h1_delta}" --argjson direct_h2 "${direct_h2_delta}" '. + {fast_path: {plain_proxy: {($protocol): $fast_path}, request_body: {($protocol): $request_body}, transport: {direct_h1: {($protocol): $direct_h1}, direct_h2: {($protocol): $direct_h2}}}}' <<<"${json}")"
    if [[ "${direct_h1_pool_delta}" != "{}" ]]; then
      json="$(jq -c --argjson direct_h1_pool "${direct_h1_pool_delta}" '. + {fast_path: ((.fast_path // {}) + {pool: (((.fast_path // {}).pool // {}) + {direct_h1: $direct_h1_pool})})}' <<<"${json}")"
    fi
    if [[ "${direct_h1_io_backend_delta_json}" != "{}" ]]; then
      json="$(jq -c --argjson direct_h1_io_backend "${direct_h1_io_backend_delta_json}" '. + {fast_path: ((.fast_path // {}) + {io_backend: (((.fast_path // {}).io_backend // {}) + {direct_h1: $direct_h1_io_backend})})}' <<<"${json}")"
    fi
    if [[ "${direct_transport}" == "direct_h2" ]]; then
      if [[ "${direct_h2_pool_delta}" != "{}" ]]; then
        json="$(jq -c --argjson direct_h2_pool "${direct_h2_pool_delta}" '. + {fast_path: ((.fast_path // {}) + {pool: (((.fast_path // {}).pool // {}) + {direct_h2: $direct_h2_pool})})}' <<<"${json}")"
      fi
    fi
    if [[ "${stage_timing_delta_json}" != "{}" ]]; then
      json="$(jq -c --argjson stage_timing "${stage_timing_delta_json}" '. + {fast_path: ((.fast_path // {}) + {stage_timing: $stage_timing})}' <<<"${json}")"
    fi
    if ! diagnostic_load_label "${label}" "${protocol}" "${host}"; then
      assert_plain_proxy_fast_path_hit_rate "${label}" "${fast_path_protocol}" "${fast_path_delta}"
    fi
    case "${direct_transport}" in
      direct_h1)
        if ! diagnostic_load_label "${label}" "${protocol}" "${host}"; then
          assert_direct_transport_hit_rate "${label}" "${fast_path_protocol}" "${direct_transport}" "${direct_h1_delta}"
        fi
        ;;
      direct_h2) ;;
      "") ;;
      *) fail_with_diagnostics "invalid direct transport gate for ${label}: ${direct_transport}" ;;
    esac
  fi
  if static_fast_path_gate_label "${label}" "${protocol}" "${host}"; then
    static_fast_path_after="$(static_fast_path_metrics "${host}" "${label}-static-fast-path-after")"
    static_fast_path_delta="$(static_fast_path_delta "${static_fast_path_before}" "${static_fast_path_after}")"
    json="$(jq -c --argjson static_fast_path "${static_fast_path_delta}" '. + {fast_path: ((.fast_path // {}) + {static_responses: $static_fast_path})}' <<<"${json}")"
  fi
  json="$(normalize_diagnostic_load_result "$(normalize_diagnostic_comparator_result "${json}")")"
  append_result "${json}"
  if diagnostic_load_label "${label}" "${protocol}" "${host}"; then
    assert_diagnostic_result "${json}"
  else
    assert_result "${json}"
  fi
  if [[ "$(jq -r '.skipped // false' <<<"${json}")" == "true" ]]; then
    sample_stats "${label}"
    return
  fi
  sample_stats "${label}"
  if [[ "${diagnostic_profiles:-0}" == "1" ]]; then
    run_diagnostic_profile_replay "${label}" "${duration}" "${protocol}" "${probe_args[@]}"
  fi
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
  if ! json="$(run_probe_json handshake \
    --label "${label}" \
    --protocol "${protocol}" \
    --host "${host}" \
    --port 8443 \
    --server-name proxy \
    --ca-cert /tls/proxy-ca.pem \
    --duration-seconds "${duration_seconds}" \
    --concurrency "${concurrency}" \
    --client-resumption "${client_resumption}" \
    --post-handshake-observe-ms "${post_handshake_observe_ms}")"; then
    if diagnostic_comparator_label "${label}"; then
      record_diagnostic_comparator_skip "${label}" handshake "${protocol}" "diagnostic comparator probe failed before producing a valid result"
      sample_stats "${label}"
      return
    fi
    fail_with_diagnostics "performance probe failed before producing a valid result: ${label}"
  fi
  if [[ "${diagnostics}" == "tls-storage" ]]; then
    after_metrics="$(server_session_storage_metrics "${host}" "${label}-metrics-after")"
    storage_delta="$(server_session_storage_delta "${before_metrics}" "${after_metrics}")"
    json="$(jq -c --argjson storage "${storage_delta}" '. + {server_session_storage: $storage}' <<<"${json}")"
  fi
  json="$(normalize_diagnostic_comparator_result "${json}")"
  append_result "${json}"
  if [[ "${result_mode}" == "strict" ]]; then
    assert_result "${json}"
  else
    assert_diagnostic_result "${json}"
  fi
  if [[ "$(jq -r '.skipped // false' <<<"${json}")" == "true" ]]; then
    sample_stats "${label}"
    return
  fi
  sample_stats "${label}"
  if [[ "${diagnostic_profiles:-0}" == "1" ]]; then
    run_diagnostic_profile_replay "${label}" "${duration_seconds}" "${protocol}" handshake \
      --label "${label}" \
      --protocol "${protocol}" \
      --host "${host}" \
      --port 8443 \
      --server-name proxy \
      --ca-cert /tls/proxy-ca.pem \
      --duration-seconds "${duration_seconds}" \
      --concurrency "${concurrency}" \
      --client-resumption "${client_resumption}" \
      --post-handshake-observe-ms "${post_handshake_observe_ms}"
  fi
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

plain_proxy_fast_path_metrics() {
  local host="$1"
  local label="$2"
  local protocol="$3"
  local attempt json
  for attempt in $(seq 1 10); do
    if json="$(run_probe_json metrics \
      --label "${label}-${attempt}" \
      --host "${host}" \
      --port 9090 \
      --authority ops.test \
      --path /metrics)"; then
      jq -c --arg protocol "${protocol}" '.fast_path.plain_proxy[$protocol] // {
        hits: 0,
        misses: 0,
        attempts: 0,
        hit_rate: null,
        miss_reasons: {}
      }' <<<"${json}"
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "metrics endpoint did not become ready for ${label}"
}

fast_path_transport_metrics() {
  local host="$1"
  local label="$2"
  local transport="$3"
  local protocol="$4"
  local attempt json
  for attempt in $(seq 1 10); do
    if json="$(run_probe_json metrics \
      --label "${label}-${attempt}" \
      --host "${host}" \
      --port 9090 \
      --authority ops.test \
      --path /metrics)"; then
      jq -c --arg transport "${transport}" --arg protocol "${protocol}" '.fast_path.transport[$transport][$protocol] // {
        hits: 0,
        misses: 0,
        attempts: 0,
        hit_rate: null,
        miss_reasons: {}
      }' <<<"${json}"
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "metrics endpoint did not become ready for ${label}"
}

direct_h1_transport_metrics() {
  fast_path_transport_metrics "$1" "$2" direct_h1 "$3"
}

direct_h2_transport_metrics() {
  fast_path_transport_metrics "$1" "$2" direct_h2 "$3"
}

fast_path_request_body_metrics() {
  local host="$1"
  local label="$2"
  local protocol="$3"
  local attempt json
  for attempt in $(seq 1 10); do
    if json="$(run_probe_json metrics \
      --label "${label}-${attempt}" \
      --host "${host}" \
      --port 9090 \
      --authority ops.test \
      --path /metrics)"; then
      jq -c --arg protocol "${protocol}" '.fast_path.request_body[$protocol] // {}' <<<"${json}"
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "metrics endpoint did not become ready for ${label}"
}

direct_h1_pool_metrics() {
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
      jq -c '.fast_path.pool.direct_h1 // {}' <<<"${json}"
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "metrics endpoint did not become ready for ${label}"
}

direct_h2_pool_metrics() {
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
      jq -c '.fast_path.pool.direct_h2 // {}' <<<"${json}"
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "metrics endpoint did not become ready for ${label}"
}

direct_h1_io_backend_metrics() {
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
      jq -c '.fast_path.io_backend.direct_h1 // {}' <<<"${json}"
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "metrics endpoint did not become ready for ${label}"
}

static_fast_path_metrics() {
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
      jq -c '.fast_path.static_responses // {}' <<<"${json}"
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "metrics endpoint did not become ready for ${label}"
}

fast_path_stage_timing_metrics() {
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
      jq -c '.fast_path.stage_timing // {}' <<<"${json}"
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "metrics endpoint did not become ready for ${label}"
}

fast_path_counter_delta() {
  local before="$1"
  local after="$2"
  jq -n -c \
    --argjson before "${before}" \
    --argjson after "${after}" \
    --argjson threshold "${h1_fast_path_min_hit_rate}" \
    'def diff($name):
       (($after[$name] // 0) - ($before[$name] // 0)) as $value
       | if $value < 0 then 0 else $value end;
     def reason_delta($reason):
       (((($after.miss_reasons // {})[$reason] // 0) - (($before.miss_reasons // {})[$reason] // 0)) as $value
        | if $value < 0 then 0 else $value end);
     (($before.miss_reasons // {}) + ($after.miss_reasons // {}) | keys_unsorted) as $reasons
     | (reduce $reasons[] as $reason ({}; .[$reason] = reason_delta($reason))) as $miss_reasons
     | (diff("hits")) as $hits
     | ([$miss_reasons[]] | add // 0) as $misses
     | ($hits + $misses) as $attempts
     | {
         hits: $hits,
         misses: $misses,
         attempts: $attempts,
         hit_rate: (if $attempts == 0 then null else ($hits / $attempts) end),
         threshold: $threshold,
         miss_reasons: $miss_reasons
       }'
}

plain_proxy_fast_path_delta() {
  fast_path_counter_delta "$1" "$2"
}

direct_h1_transport_delta() {
  fast_path_counter_delta "$1" "$2"
}

direct_h2_transport_delta() {
  fast_path_counter_delta "$1" "$2"
}

counter_map_delta() {
  local before="$1"
  local after="$2"
  jq -n -c \
    --argjson before "${before}" \
    --argjson after "${after}" \
    'def positive_delta($name):
       ((($after[$name] // 0) - ($before[$name] // 0)) as $value
        | if $value < 0 then 0 else $value end);
     (($before + $after) | keys_unsorted) as $names
     | reduce $names[] as $name ({}; .[$name] = positive_delta($name))'
}

nested_counter_map_delta() {
  local before="$1"
  local after="$2"
  jq -n -c \
    --argjson before "${before}" \
    --argjson after "${after}" \
    'def sample($root; $path): ($root | getpath($path)) // 0;
     def positive_delta($path):
       ((sample($after; $path) - sample($before; $path)) as $value
        | if $value < 0 then 0 else $value end);
     ([($before | paths(scalars)), ($after | paths(scalars))] | unique) as $paths
     | reduce $paths[] as $path ({}; setpath($path; positive_delta($path)))'
}

nonzero_counter_map() {
  local value="$1"
  jq -c 'with_entries(select((.value // 0) != 0))' <<<"${value}"
}

nonzero_nested_counter_map() {
  local value="$1"
  jq -c '
    def prune:
      if type == "object" then
        with_entries(.value |= prune | select(.value != {} and .value != 0))
      else
        .
      end;
    prune
  ' <<<"${value}"
}

stage_timing_delta() {
  local before="$1"
  local after="$2"
  jq -n -c \
    --argjson before "${before}" \
    --argjson after "${after}" \
    'def sample($root; $path):
       (((($root[$path[0]] // {})[$path[1]] // {})[$path[2]] // {})[$path[3]] // {});
     def positive_delta($path; $field):
       ((sample($after; $path)[$field] // 0) - (sample($before; $path)[$field] // 0)) as $value
       | if $value < 0 then 0 else $value end;
     ([($before | paths(objects) | select(length == 4)), ($after | paths(objects) | select(length == 4))] | unique) as $paths
     | reduce $paths[] as $path ({};
         (positive_delta($path; "count")) as $count
         | (positive_delta($path; "total_ns")) as $total_ns
         | if $count == 0 and $total_ns == 0 then .
           else .[$path[0]][$path[1]][$path[2]][$path[3]] = {
             count: $count,
             total_ns: $total_ns,
             avg_ns: (if $count == 0 then null else ($total_ns / $count) end)
           }
           end)'
}

static_fast_path_delta() {
  local before="$1"
  local after="$2"
  jq -n -c \
    --argjson before "${before}" \
    --argjson after "${after}" \
    'def positive_delta($source; $outcome):
       (((($after[$source] // {})[$outcome] // 0) - (($before[$source] // {})[$outcome] // 0)) as $value
        | if $value < 0 then 0 else $value end);
     (($before + $after) | keys_unsorted) as $sources
     | reduce $sources[] as $source ({};
         (($before[$source] // {}) + ($after[$source] // {}) | keys_unsorted) as $outcomes
         | .[$source] = (reduce $outcomes[] as $outcome ({}; .[$outcome] = positive_delta($source; $outcome))))'
}

static_fast_path_gate_label() {
  local label="$1"
  local protocol="$2"
  local host="$3"
  [[ "${host}" == "oxibelt" && "${label}:${protocol}" == "oxibelt-static-16k-h1c:h1c" ]]
}

plain_proxy_fast_path_gate_protocol() {
  local label="$1"
  local protocol="$2"
  local host="$3"
  if [[ "${host}" != "oxibelt" ]]; then
    return
  fi
  case "${label}:${protocol}" in
    oxibelt-h1-keepalive:h1) printf 'h1' ;;
    oxibelt-h2:h2) printf 'h2' ;;
    oxibelt-h3:h3) printf 'h3' ;;
    oxibelt-runtime-direct-h1-*-h1:h1) printf 'h1' ;;
    oxibelt-runtime-direct-h1-*-h2:h2) printf 'h2' ;;
    oxibelt-runtime-direct-h1-*-h3:h3) printf 'h3' ;;
    oxibelt-metrics-basic-h2:h2) printf 'h2' ;;
    oxibelt-metrics-basic-h3:h3) printf 'h3' ;;
    oxibelt-metrics-detailed-h2:h2) printf 'h2' ;;
    oxibelt-metrics-detailed-h3:h3) printf 'h3' ;;
    oxibelt-h3-inline-fast-path-experiment:h3) printf 'h3' ;;
    oxibelt-pool*-conc*-h2:h2) printf 'h2' ;;
    oxibelt-pool*-conc*-h3:h3) printf 'h3' ;;
    oxibelt-h2-upstream-h2c:h2) printf 'h2' ;;
    oxibelt-h2-upstream-h2:h2) printf 'h2' ;;
    oxibelt-h3-upstream-h2c:h3) printf 'h3' ;;
    oxibelt-h3-upstream-h2:h3) printf 'h3' ;;
  esac
}

direct_transport_gate_transport() {
  local label="$1"
  local protocol="$2"
  local host="$3"
  if [[ "${host}" != "oxibelt" ]]; then
    return
  fi
  case "${label}:${protocol}" in
    oxibelt-h1-keepalive:h1|oxibelt-h2:h2|oxibelt-h3:h3|oxibelt-runtime-direct-h1-*-h1:h1|oxibelt-runtime-direct-h1-*-h2:h2|oxibelt-runtime-direct-h1-*-h3:h3|oxibelt-metrics-basic-h2:h2|oxibelt-metrics-basic-h3:h3|oxibelt-metrics-detailed-h2:h2|oxibelt-metrics-detailed-h3:h3|oxibelt-h3-inline-fast-path-experiment:h3|oxibelt-pool*-conc*-h2:h2|oxibelt-pool*-conc*-h3:h3) printf 'direct_h1' ;;
    oxibelt-h2-upstream-h2c:h2|oxibelt-h2-upstream-h2:h2|oxibelt-h3-upstream-h2c:h3|oxibelt-h3-upstream-h2:h3) printf 'direct_h2' ;;
  esac
}

assert_plain_proxy_fast_path_hit_rate() {
  local label="$1"
  local protocol="$2"
  local fast_path="$3"
  local attempts hit_rate protocol_name
  protocol_name="${protocol^^}"
  attempts="$(jq -r '.attempts // 0' <<<"${fast_path}")"
  if [[ "${attempts}" == "0" ]]; then
    handle_regression_gate_violation "OxiBelt ${label} fast-path gate failed: no ${protocol_name} plain-proxy fast-path decision samples were recorded"
    return
  fi
  hit_rate="$(jq -r '.hit_rate // empty' <<<"${fast_path}")"
  if [[ -z "${hit_rate}" ]]; then
    handle_regression_gate_violation "OxiBelt ${label} fast-path gate failed: missing ${protocol_name} hit-rate evidence"
    return
  fi
  if jq -e --argjson hit_rate "${hit_rate}" --argjson min "${h1_fast_path_min_hit_rate}" '$hit_rate < $min' >/dev/null; then
    handle_regression_gate_violation "OxiBelt ${label} fast-path gate failed: hit rate ${hit_rate} < ${h1_fast_path_min_hit_rate}; details: ${fast_path}"
  fi
}

assert_direct_transport_hit_rate() {
  local label="$1"
  local protocol="$2"
  local transport="$3"
  local fast_path="$4"
  local attempts hit_rate protocol_name transport_name
  protocol_name="${protocol^^}"
  transport_name="${transport//_/ }"
  attempts="$(jq -r '.attempts // 0' <<<"${fast_path}")"
  if [[ "${attempts}" == "0" ]]; then
    handle_regression_gate_violation "OxiBelt ${label} ${transport_name} transport gate failed: no ${protocol_name} ${transport_name} transport samples were recorded"
    return
  fi
  hit_rate="$(jq -r '.hit_rate // empty' <<<"${fast_path}")"
  if [[ -z "${hit_rate}" ]]; then
    handle_regression_gate_violation "OxiBelt ${label} ${transport_name} transport gate failed: missing ${protocol_name} ${transport_name} hit-rate evidence"
    return
  fi
  if jq -e --argjson hit_rate "${hit_rate}" --argjson min "${h1_fast_path_min_hit_rate}" '$hit_rate < $min' >/dev/null; then
    handle_regression_gate_violation "OxiBelt ${label} ${transport_name} transport gate failed: hit rate ${hit_rate} < ${h1_fast_path_min_hit_rate}; details: ${fast_path}"
  fi
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
  shift 5
  local extra_args=("$@")
  local json
  json="$(run_probe_json stress \
    --label "${label}" \
    --mode "${mode}" \
    --host oxibelt \
    --port 8080 \
    --authority example.test \
    --connections "${connections}" \
    --duration-seconds "${duration}" \
    --bytes "${bytes}" \
    "${extra_args[@]}")"
  append_result "${json}"
  assert_result "${json}"
  sample_stats "${label}"
  if [[ "${diagnostic_profiles:-0}" == "1" ]]; then
    run_diagnostic_profile_replay "${label}" "${duration}" "${mode}" stress \
      --label "${label}" \
      --mode "${mode}" \
      --host oxibelt \
      --port 8080 \
      --authority example.test \
      --connections "${connections}" \
      --duration-seconds "${duration}" \
      --bytes "${bytes}" \
      "${extra_args[@]}"
  fi
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

run_resource_baseline_load() {
  local label="$1"
  local protocol="$2"
  local path="$3"
  local conc="$4"
  local json
  if ! json="$(run_probe_json load \
    --label "${label}" \
    --protocol "${protocol}" \
    --host oxibelt \
    --port 8443 \
    --server-name proxy \
    --authority example.test \
    --path "${path}" \
    --ca-cert /tls/proxy-ca.pem \
    --duration-seconds 1 \
    --warmup-seconds 0 \
    --concurrency "${conc}" \
    --expect-status 200)"; then
    return 1
  fi
  assert_diagnostic_result "${json}"
}

warm_oxibelt_aggressive_resource_baseline() {
  local warmup_concurrency="${concurrency}"
  if (( warmup_concurrency > 4 )); then
    warmup_concurrency=4
  fi
  run_resource_baseline_load "oxibelt-aggressive-resource-warmup-h1" h1 "/ready?body=ok" "${warmup_concurrency}" || return 1
  run_resource_baseline_load "oxibelt-aggressive-resource-warmup-h2" h2 "/ready?body=ok" "${warmup_concurrency}" || return 1
  run_resource_baseline_load "oxibelt-aggressive-resource-warmup-h3" h3 "/ready?body=ok" "${warmup_concurrency}" || return 1
}

wait_for_tls_proxy() {
  local host="$1"
  local attempt json
  for attempt in $(seq 1 30); do
    if [[ -n "${active_proxy_container}" && "$(docker inspect -f '{{.State.Running}}' "${active_proxy_container}" 2>/dev/null || echo false)" != "true" ]]; then
      return 1
    fi
    if json="$(run_probe_json load \
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
      --expect-status 200 2>/dev/null)"; then
      if jq -e '(.requests // 0) > 0 and (.errors // 0) == 0' >/dev/null <<<"${json}"; then
        return 0
      fi
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
  if [[ -n "${active_remote_signer_container}" ]]; then
    docker logs "${active_remote_signer_container}" >"${logs_dir}/${active_remote_signer_container}.log" 2>&1 || true
    docker rm -f "${active_remote_signer_container}" >/dev/null 2>&1 || true
    active_remote_signer_container=""
  fi
  if [[ -n "${active_remote_signer_volume}" ]]; then
    docker volume rm "${active_remote_signer_volume}" >/dev/null 2>&1 || true
    active_remote_signer_volume=""
  fi
  if [[ -n "${active_remote_signer_cert_volume}" ]]; then
    docker volume rm "${active_remote_signer_cert_volume}" >/dev/null 2>&1 || true
    active_remote_signer_cert_volume=""
  fi
}

assert_active_proxy_container_running() {
  local description="$1"
  if [[ -z "${active_proxy_container}" ]]; then
    fail_with_diagnostics "${description} was not started before benchmark data collection"
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "${active_proxy_container}" 2>/dev/null || echo false)" != "true" ]]; then
    fail_with_diagnostics "${description} exited before benchmark data collection"
  fi
}

start_oxibelt() {
  local scenario="$1"
  local alias_name="$2"
  shift 2
  local fixture_dir="${fixture_root}/oxibelt/${scenario}"
  local container="oxibelt-perf-${scenario}-${run_id}"
  local remote_signer=0
  local remote_signer_token=""
  local remote_signer_container="oxibelt-perf-keysigner-${scenario}-${run_id}"
  local remote_signer_volume="oxibelt-perf-keysigner-sock-${scenario}-${run_id}"
  local remote_signer_cert_volume="oxibelt-perf-keysigner-cert-${scenario}-${run_id}"
  local remote_signer_cert_seed_container="oxibelt-perf-keysigner-cert-seed-${scenario}-${run_id}"
  local detailed_hot_path_diagnostics=0
  local metrics_disabled=0
  local oxibelt_config
  local -a oxibelt_env_args=()
  local -a remote_signer_args=()
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --detailed-hot-path-diagnostics)
        detailed_hot_path_diagnostics=1
        shift
        ;;
      --metrics-disabled)
        metrics_disabled=1
        shift
        ;;
      *)
        oxibelt_env_args+=("$1")
        shift
        ;;
    esac
  done
  stop_active_proxy
  if [[ ! -d "${fixture_dir}/config" ]]; then
    fail_with_diagnostics "missing OxiBelt performance fixture: ${scenario}"
  fi
  mkdir -p "${configs_dir}/oxibelt-${scenario}"
  cp -R "${fixture_dir}/." "${configs_dir}/oxibelt-${scenario}/"
  oxibelt_config="${configs_dir}/oxibelt-${scenario}/config/oxibelt.toml"
  if [[ "${detailed_hot_path_diagnostics}" == "1" ]]; then
    sed -i 's/^[[:space:]]*detail = "basic"[[:space:]]*$/detail = "detailed"/' \
      "${oxibelt_config}"
  fi
  if [[ "${metrics_disabled}" == "1" ]]; then
    awk '
      /^[[:space:]]*\[/ {
        in_metrics = ($0 ~ /^[[:space:]]*\[metrics\][[:space:]]*$/)
      }
      in_metrics && /^[[:space:]]*enabled[[:space:]]*=/ {
        sub(/=.*/, "= false")
      }
      { print }
    ' "${oxibelt_config}" >"${oxibelt_config}.tmp"
    mv "${oxibelt_config}.tmp" "${oxibelt_config}"
  fi
  if grep -Eq '^[[:space:]]*\[tls[.]remote_signer\]' "${fixture_dir}/config/oxibelt.toml"; then
    remote_signer=1
  fi
  mkdir -p "${configs_dir}/oxibelt-${scenario}/cert"
  cp "${tls_dir}/fullchain.pem" "${configs_dir}/oxibelt-${scenario}/cert/fullchain.pem"
  cp "${tls_dir}/quic-host-key.b64" "${configs_dir}/oxibelt-${scenario}/cert/quic-host-key.b64"
  if [[ "${remote_signer}" != "1" ]]; then
    cp "${tls_dir}/privkey.pem" "${configs_dir}/oxibelt-${scenario}/cert/privkey.pem"
  fi

  if [[ "${remote_signer}" == "1" ]]; then
    remote_signer_token="$(openssl rand -base64 32)"
    printf '%s\n' "${remote_signer_token}" >"${configs_dir}/oxibelt-${scenario}/cert/keysigner-token.b64"
    chmod 0644 "${configs_dir}/oxibelt-${scenario}/cert/keysigner-token.b64"
    docker volume create --label "${test_label}" "${remote_signer_volume}" >/dev/null
    docker volume create --label "${test_label}" "${remote_signer_cert_volume}" >/dev/null
    docker create \
      --name "${remote_signer_cert_seed_container}" \
      --label "${test_label}" \
      --user 0:0 \
      --mount "type=volume,src=${remote_signer_cert_volume},dst=/cert" \
      --entrypoint sh \
      "${oxibelt_image}" \
      -c 'chown 10002:10002 /cert /cert/privkey.pem /cert/keysigner-token.b64 && chmod 0550 /cert && chmod 0400 /cert/privkey.pem /cert/keysigner-token.b64' >/dev/null
    docker cp "${tls_dir}/privkey.pem" "${remote_signer_cert_seed_container}:/cert/privkey.pem"
    docker cp "${configs_dir}/oxibelt-${scenario}/cert/keysigner-token.b64" "${remote_signer_cert_seed_container}:/cert/keysigner-token.b64"
    docker start -a "${remote_signer_cert_seed_container}" >/dev/null
    docker rm "${remote_signer_cert_seed_container}" >/dev/null
    docker run --rm \
      --label "${test_label}" \
      --user 0:0 \
      --mount "type=volume,src=${remote_signer_volume},dst=/run/oxibelt-keysigner" \
      --entrypoint sh \
      "${oxibelt_image}" \
      -c 'chown 10002:10002 /run/oxibelt-keysigner && chmod 0770 /run/oxibelt-keysigner' >/dev/null
    docker create \
      --name "${remote_signer_container}" \
      --label "${test_label}" \
      --user 10002:10002 \
      --read-only \
      --cap-drop=ALL \
      --security-opt no-new-privileges \
      --network "${network_name}" \
      --mount "type=volume,src=${remote_signer_volume},dst=/run/oxibelt-keysigner" \
      --mount "type=volume,src=${remote_signer_cert_volume},dst=/etc/oxibelt/cert,readonly" \
      --entrypoint /usr/local/bin/oxibelt-keysigner \
      "${oxibelt_image}" \
      --socket /run/oxibelt-keysigner/sign.sock \
      --key edge-default=/etc/oxibelt/cert/privkey.pem \
      --token-file /etc/oxibelt/cert/keysigner-token.b64 \
      --token-reload-interval-ms 1000 \
      --socket-mode 0660 \
      --allow-peer-uid 10001 \
      --max-connections 1024 \
      --io-timeout-ms 5000 >/dev/null
    docker start "${remote_signer_container}" >/dev/null
    active_remote_signer_container="${remote_signer_container}"
    active_remote_signer_volume="${remote_signer_volume}"
    active_remote_signer_cert_volume="${remote_signer_cert_volume}"
    for _attempt in $(seq 1 100); do
      if docker exec "${remote_signer_container}" sh -c 'test -S /run/oxibelt-keysigner/sign.sock' >/dev/null 2>&1; then
        break
      fi
      if [[ "$(docker inspect -f '{{.State.Running}}' "${remote_signer_container}" 2>/dev/null || echo false)" != "true" ]]; then
        fail_with_diagnostics "OxiBelt remote signer exited before creating its socket for ${scenario}"
      fi
      sleep 0.05
    done
    if ! docker exec "${remote_signer_container}" sh -c 'test -S /run/oxibelt-keysigner/sign.sock' >/dev/null 2>&1; then
      fail_with_diagnostics "OxiBelt remote signer socket was not created for ${scenario}"
    fi
    remote_signer_args+=(
      --group-add 10002
      --mount "type=volume,src=${remote_signer_volume},dst=/run/oxibelt-keysigner"
    )
  fi

  docker create \
    --name "${container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias "${alias_name}" \
    -e OXIBELT_INSTANCE_ID="perf-${scenario}" \
    "${oxibelt_env_args[@]}" \
    "${remote_signer_args[@]}" \
    "${oxibelt_image}" >/dev/null
  docker cp "${configs_dir}/oxibelt-${scenario}/config/." "${container}:/etc/oxibelt/config"
  if [[ "${remote_signer}" == "1" ]]; then
    docker cp "${tls_dir}/fullchain.pem" "${container}:/etc/oxibelt/cert/fullchain.pem"
    docker cp "${tls_dir}/quic-host-key.b64" "${container}:/etc/oxibelt/cert/quic-host-key.b64"
    docker cp "${configs_dir}/oxibelt-${scenario}/cert/keysigner-token.b64" "${container}:/etc/oxibelt/cert/keysigner-token.b64"
  else
    docker cp "${tls_dir}/." "${container}:/etc/oxibelt/cert"
  fi
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

start_openresty() {
  local container="openresty-perf-${run_id}"
  stop_active_proxy
  mkdir -p "${configs_dir}/openresty"
  cp "${fixture_root}/openresty/default.conf" "${configs_dir}/openresty/default.conf"
  cp -R "${tls_dir}" "${configs_dir}/openresty/cert"

  docker create \
    --name "${container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias openresty \
    "${openresty_image}" >/dev/null
  docker cp "${fixture_root}/openresty/default.conf" "${container}:/etc/nginx/conf.d/default.conf"
  docker cp "${tls_dir}/fullchain.pem" "${container}:/etc/nginx/fullchain.pem"
  docker cp "${tls_dir}/privkey.pem" "${container}:/etc/nginx/privkey.pem"
  docker cp "${static_dir}/." "${container}:/srv/static"
  docker start "${container}" >/dev/null
  active_proxy_container="${container}"
  if ! wait_for_tls_proxy openresty; then
    fail_with_diagnostics "OpenResty performance proxy did not become ready"
  fi
  assert_active_proxy_container_running "OpenResty performance proxy"
}

detect_nginx_h3() {
  if docker run --rm "${nginx_image}" nginx -V 2>&1 | grep -F -- '--with-http_v3_module' >/dev/null; then
    nginx_h3_supported=1
  else
    nginx_h3_supported=0
  fi
}

resolve_nginx_h3_mode() {
  case "${nginx_h3_mode_override}" in
    auto)
      if [[ "${nginx_h3_supported}" == "1" ]]; then
        echo optional
      else
        echo disabled
      fi
      ;;
    required)
      if [[ "${nginx_h3_supported}" != "1" ]]; then
        fail_with_diagnostics "OXIBELT_NGINX_H3_MODE=required but nginx image ${nginx_image} does not report --with-http_v3_module"
      fi
      echo required
      ;;
    optional)
      if [[ "${nginx_h3_supported}" == "1" ]]; then
        echo optional
      else
        echo disabled
      fi
      ;;
    disabled)
      echo disabled
      ;;
  esac
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

run_metrics_mode_h3_load() {
  local label="$1"
  local host="$2"
  local h3_mode="$3"
  case "${h3_mode}" in
    required)
      if h3_probe_succeeds "${host}"; then
        run_load "${label}" h3 "${host}" "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
      else
        fail_with_diagnostics "mandatory HTTP/3 probe failed for ${label}: functional QUIC probe did not complete"
      fi
      ;;
    optional)
      if h3_probe_succeeds "${host}"; then
        run_load "${label}" h3 "${host}" "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
      else
        record_skip "${label}" load h3 "optional HTTP/3 support was detected, but a functional QUIC probe did not complete"
      fi
      ;;
    disabled)
      record_skip "${label}" load h3 "HTTP/3 is not available for this comparator image"
      ;;
    *)
      fail_with_diagnostics "invalid HTTP/3 performance mode for ${label}: ${h3_mode}"
      ;;
  esac
}

run_metrics_mode_loads_for_host() {
  local comparator="$1"
  local host="$2"
  local mode="$3"
  local h3_mode="$4"
  run_load "${comparator}-metrics-${mode}-h2" h2 "${host}" "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"
  run_metrics_mode_h3_load "${comparator}-metrics-${mode}-h3" "${host}" "${h3_mode}"
}

run_oxibelt_h2_split_loads() {
  start_oxibelt baseline-upstream-h2c oxibelt
  run_load "oxibelt-h2-upstream-h2c" h2 oxibelt "/perf/h2c?body=ok" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-h3-upstream-h2c" h3 oxibelt "/perf/h2c?body=ok" "${duration_seconds}" "${concurrency}"

  start_oxibelt baseline-upstream-h2 oxibelt
  run_load "oxibelt-h2-upstream-h2" h2 oxibelt "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-h3-upstream-h2" h3 oxibelt "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"

  if [[ "${profile}" == "benchmark" ]]; then
    start_oxibelt baseline-h2-adaptive-window oxibelt
    run_load "oxibelt-h2-adaptive-window" h2 oxibelt "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"
  fi
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
  run_load "oxibelt-cache-noncacheable-miss" h2 oxibelt "/perf/cache-noncacheable-miss?body_repeat=4096&cache_control=no-store" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-cache-cold-fill" h2 oxibelt "/perf/cache-cold-fill?body_repeat=4096&cache_control=public" "${duration_seconds}" "${concurrency}" --unique-query-param fill_id
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

pool_experiment_scenario_for_cap() {
  local cap="$1"
  case "${cap}" in
    128) printf 'baseline' ;;
    256) printf 'baseline-pool-256' ;;
    512) printf 'baseline-pool-512' ;;
  esac
}

run_pool_concurrency_experiments_group() {
  if ! has_comparator oxibelt; then
    return
  fi

  local -a pool_caps concurrency_presets
  IFS=',' read -r -a pool_caps <<<"${pool_experiment_caps}"
  IFS=',' read -r -a concurrency_presets <<<"${pool_experiment_concurrency_presets}"

  local pool_cap scenario preset
  for pool_cap in "${pool_caps[@]}"; do
    if ! [[ "${pool_cap}" =~ ^[0-9]+$ ]]; then
      record_skip "oxibelt-pool${pool_cap}-invalid-h2" load h2 "invalid pool cap preset"
      record_skip "oxibelt-pool${pool_cap}-invalid-h3" load h3 "invalid pool cap preset"
      continue
    fi
    scenario="$(pool_experiment_scenario_for_cap "${pool_cap}")"
    if [[ -z "${scenario}" ]]; then
      record_skip "oxibelt-pool${pool_cap}-unsupported-h2" load h2 "unsupported pool cap preset"
      record_skip "oxibelt-pool${pool_cap}-unsupported-h3" load h3 "unsupported pool cap preset"
      continue
    fi

    start_oxibelt "${scenario}" oxibelt --detailed-hot-path-diagnostics
    for preset in "${concurrency_presets[@]}"; do
      if ! [[ "${preset}" =~ ^[1-9][0-9]*$ ]]; then
        record_skip "oxibelt-pool${pool_cap}-conc${preset}-h2" load h2 "invalid pool-concurrency preset"
        record_skip "oxibelt-pool${pool_cap}-conc${preset}-h3" load h3 "invalid pool-concurrency preset"
        continue
      fi
      run_load "oxibelt-pool${pool_cap}-conc${preset}-h2" h2 oxibelt "/perf/h2?body=ok" "${duration_seconds}" "${preset}"
      if h3_probe_succeeds oxibelt; then
        run_load "oxibelt-pool${pool_cap}-conc${preset}-h3" h3 oxibelt "/perf/h3?body=ok" "${duration_seconds}" "${preset}"
      else
        fail_with_diagnostics "mandatory HTTP/3 probe failed for pool cap ${pool_cap} concurrency ${preset}: functional QUIC probe did not complete"
      fi
    done
  done
}

run_oxibelt_aggressive_long_run() {
  local h1_soak h2_soak h3_soak stress_duration
  h1_soak=$(( soak_seconds / 3 ))
  h2_soak=$(( soak_seconds / 3 ))
  h3_soak=$(( soak_seconds - h1_soak - h2_soak ))
  if (( h1_soak < 1 )); then h1_soak=1; fi
  if (( h2_soak < 1 )); then h2_soak=1; fi
  if (( h3_soak < 1 )); then h3_soak=1; fi
  stress_duration="${aggressive_stress_seconds}"

  start_oxibelt "${oxibelt_aggressive_scenario}" oxibelt
  warm_oxibelt_aggressive_resource_baseline || fail_with_diagnostics "mandatory HTTP/3 probe failed for OxiBelt aggressive long-run"
  sample_resource_snapshot "aggressive-before"
  run_load "oxibelt-aggressive-soak-h1" h1 oxibelt "/perf/aggressive-soak-h1?body=ok" "${h1_soak}" "${concurrency}"
  run_load "oxibelt-aggressive-soak-h2" h2 oxibelt "/perf/aggressive-soak-h2?body=ok" "${h2_soak}" "${concurrency}"
  run_load "oxibelt-aggressive-soak-h3" h3 oxibelt "/perf/aggressive-soak-h3?body=ok" "${h3_soak}" "${concurrency}"

  run_stress "oxibelt-aggressive-slow-post" slow-post 32 "${stress_duration}" 1048576 \
    --path "/perf/aggressive-slow-post?json=1" \
    --chunk-bytes 512 \
    --chunk-delay-ms 100
  run_stress "oxibelt-aggressive-slow-response" slow-response 16 "${stress_duration}" 65536 \
    --path "/perf/aggressive-slow-response?body_repeat=65536&response_delay_ms=100&response_chunk_delay_ms=50&response_chunk_bytes=512" \
    --expect-status 200
  run_stress "oxibelt-aggressive-h2-rapid-stream-churn" h2-rapid-stream-churn 16 "${stress_duration}" 1024 \
    --protocol h2 \
    --port 8443 \
    --server-name proxy \
    --ca-cert /tls/proxy-ca.pem \
    --path "/perf/aggressive-h2-churn?body=ok" \
    --expect-status 200 \
    --streams-per-connection 128
  run_stress "oxibelt-aggressive-h2-cl0-data" h2-cl0-data 32 "${stress_duration}" 8 \
    --protocol h2 \
    --port 8443 \
    --server-name proxy \
    --ca-cert /tls/proxy-ca.pem \
    --path "/perf/aggressive-h2-cl0-data" \
    --chunk-bytes 8
  run_stress "oxibelt-aggressive-h3-cl0-data" h3-cl0-data 16 "${stress_duration}" 8 \
    --protocol h3 \
    --port 8443 \
    --server-name proxy \
    --ca-cert /tls/proxy-ca.pem \
    --path "/perf/aggressive-h3-cl0-data" \
    --chunk-bytes 8

  sample_resource_snapshot "aggressive-after-stress"
  if (( resource_settle_seconds > 0 )); then
    sleep "${resource_settle_seconds}"
  fi
  sample_resource_snapshot "aggressive-after"
  assert_resource_drift "aggressive-before" "aggressive-after"
}

run_reverse_proxy_group() {
  local ran_oxibelt=0 ran_nginx=0 ran_caddy=0 ran_openresty=0
  local nginx_h3_mode=disabled

  # Primary comparator rows run before diagnostics so external tool failures
  # cannot erase quorum evidence for nginx/Caddy/OpenResty reverse-proxy rows.
  if has_comparator oxibelt; then
    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
    run_common_loads oxibelt oxibelt required
    ran_oxibelt=1
  fi

  if has_comparator nginx; then
    start_nginx
    nginx_h3_mode="$(resolve_nginx_h3_mode)"
    run_common_loads nginx nginx "${nginx_h3_mode}"
    ran_nginx=1
  fi

  if has_comparator caddy; then
    start_caddy
    run_common_loads caddy caddy required
    ran_caddy=1
  fi

  if has_comparator openresty; then
    start_openresty
    run_common_loads openresty openresty required
    ran_openresty=1
  fi

  if (( ran_oxibelt )); then
    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
    run_external_benchmarks_for_comparator oxibelt oxibelt required
    assert_oxibelt_tcp_baseline
    run_oxibelt_h2_split_loads
    start_oxibelt "${oxibelt_handshake_scenario}" oxibelt
    run_handshake "oxibelt-tls-handshake-h2" h2 oxibelt
    run_handshake_resumption_diagnostic "oxibelt-tls-handshake-h2-resumption-diagnostic" h2 oxibelt
    run_oxibelt_tls_resumption_handshake_rows
  fi

  if (( ran_nginx )); then
    start_nginx
    run_external_benchmarks_for_comparator nginx nginx "${nginx_h3_mode}"
    run_handshake "nginx-tls-handshake-h2" h2 nginx
  fi

  if (( ran_caddy )); then
    start_caddy
    run_external_benchmarks_for_comparator caddy caddy required
    run_handshake "caddy-tls-handshake-h2" h2 caddy
  fi

  if (( ran_openresty )); then
    start_openresty
    run_external_benchmarks_for_comparator openresty openresty required
    run_handshake "openresty-tls-handshake-h2" h2 openresty
  fi
}

run_static_files_group() {
  if has_comparator oxibelt; then
    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
    run_static_loads oxibelt oxibelt required
  fi

  if has_comparator nginx; then
    start_nginx
    nginx_h3_mode="$(resolve_nginx_h3_mode)"
    run_static_loads nginx nginx "${nginx_h3_mode}"
  fi

  if has_comparator caddy; then
    start_caddy
    run_static_loads caddy caddy required
  fi

  if has_comparator openresty; then
    start_openresty
    run_static_loads openresty openresty required
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

append_remote_signer_overhead_summary() {
  local scenario local_label remote_label local_json remote_json
  {
    echo
    echo "Remote signer overhead:"
    echo
    echo "| Scenario | Remote signer throughput | Throughput delta | Remote signer p99 | p99 delta |"
    echo "| --- | --- | --- | --- | --- |"
  } >>"${summary_md}"

  for scenario in h1-keepalive h2 h3 tls-handshake-h2; do
    local_label="oxibelt-local-key-${scenario}"
    remote_label="oxibelt-remote-signer-${scenario}"
    local_json="$(jq -c --arg label "${local_label}" 'select(.label == $label and ((.skipped // false) | not))' "${results_jsonl}" | tail -n 1)"
    remote_json="$(jq -c --arg label "${remote_label}" 'select(.label == $label and ((.skipped // false) | not))' "${results_jsonl}" | tail -n 1)"
    if [[ -z "${local_json}" || -z "${remote_json}" ]]; then
      printf '| `%s` | unavailable | unavailable | unavailable | unavailable |\n' "${scenario}" >>"${summary_md}"
      continue
    fi
    jq -nr \
      --arg scenario "${scenario}" \
      --argjson local "${local_json}" \
      --argjson remote "${remote_json}" '
        def rate($row): ($row.rps // $row.handshake_per_sec // 0);
        def percent($value): $value * 100.0;
        def fmt($value): (($value * 100.0 | round) / 100.0 | tostring);
        (rate($local)) as $local_rate |
        (rate($remote)) as $remote_rate |
        ($local.p99_ms // 0) as $local_p99 |
        ($remote.p99_ms // 0) as $remote_p99 |
        if $local_rate <= 0 or $remote_rate <= 0 or $local_p99 <= 0 or $remote_p99 <= 0 then
          "| `" + $scenario + "` | unavailable | unavailable | unavailable | unavailable |"
        else
          ($remote_rate / $local_rate) as $throughput_ratio |
          ($remote_p99 / $local_p99) as $p99_ratio |
          "| `" + $scenario + "` | " + fmt(percent($throughput_ratio)) + "% of local key | " + fmt(percent($throughput_ratio - 1.0)) + "% | " + fmt(percent($p99_ratio)) + "% of local key | " + fmt(percent($p99_ratio - 1.0)) + "% |"
        end
      ' >>"${summary_md}"
  done
}

run_remote_signer_group() {
  if ! has_comparator oxibelt; then
    return
  fi

  start_oxibelt baseline oxibelt
  run_load "oxibelt-local-key-h1-keepalive" h1 oxibelt "/perf/h1?body=ok" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-local-key-h2" h2 oxibelt "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"
  if h3_probe_succeeds oxibelt; then
    run_load "oxibelt-local-key-h3" h3 oxibelt "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
  else
    fail_with_diagnostics "mandatory HTTP/3 probe failed for local-key remote signer comparison"
  fi

  start_oxibelt remote-signer oxibelt
  run_load "oxibelt-remote-signer-h1-keepalive" h1 oxibelt "/perf/h1?body=ok" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-remote-signer-h2" h2 oxibelt "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"
  if h3_probe_succeeds oxibelt; then
    run_load "oxibelt-remote-signer-h3" h3 oxibelt "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
  else
    fail_with_diagnostics "mandatory HTTP/3 probe failed for remote signer comparison"
  fi

  start_oxibelt baseline-accept-1 oxibelt
  run_handshake "oxibelt-local-key-tls-handshake-h2" h2 oxibelt

  start_oxibelt remote-signer-accept-1 oxibelt
  run_handshake "oxibelt-remote-signer-tls-handshake-h2" h2 oxibelt

  append_remote_signer_overhead_summary
}

run_pool_concurrency_group() {
  run_pool_concurrency_experiments_group
}

run_runtime_direct_h1_group() {
  if ! has_comparator oxibelt; then
    return
  fi

  start_oxibelt "${oxibelt_baseline_scenario}" oxibelt --detailed-hot-path-diagnostics
  run_load "oxibelt-runtime-direct-h1-control-h1" h1 oxibelt "/perf/h1?body=ok" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-runtime-direct-h1-control-h2" h2 oxibelt "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"
  if h3_probe_succeeds oxibelt; then
    run_load "oxibelt-runtime-direct-h1-control-h3" h3 oxibelt "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
  else
    fail_with_diagnostics "mandatory HTTP/3 probe failed for direct-H1 runtime control rows"
  fi

  start_oxibelt "${oxibelt_baseline_scenario}" oxibelt \
    --detailed-hot-path-diagnostics \
    -e OXIBELT_EXPERIMENTAL_DIRECT_H1_IO=compio \
    -e OXIBELT_EXPERIMENTAL_DIRECT_H1_IO_ACK=benchmark-only
  run_load "oxibelt-runtime-direct-h1-experiment-h1" h1 oxibelt "/perf/h1?body=ok" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-runtime-direct-h1-experiment-h2" h2 oxibelt "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"
  if h3_probe_succeeds oxibelt; then
    run_load "oxibelt-runtime-direct-h1-experiment-h3" h3 oxibelt "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
  else
    fail_with_diagnostics "mandatory HTTP/3 probe failed for direct-H1 runtime experiment rows"
  fi

  start_oxibelt "${oxibelt_baseline_scenario}" oxibelt \
    --detailed-hot-path-diagnostics \
    -e OXIBELT_EXPERIMENTAL_H3_INLINE_FAST_PATH=benchmark-only \
    -e OXIBELT_EXPERIMENTAL_H3_INLINE_FAST_PATH_ACK=benchmark-only
  if h3_probe_succeeds oxibelt; then
    run_load "oxibelt-h3-inline-fast-path-experiment" h3 oxibelt "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
  else
    fail_with_diagnostics "mandatory HTTP/3 probe failed for H3 inline fast-path experiment row"
  fi
}

run_metrics_mode_group() {
  local nginx_h3_mode=disabled
  if has_comparator nginx; then
    start_nginx
    nginx_h3_mode="$(resolve_nginx_h3_mode)"
    run_metrics_mode_loads_for_host nginx nginx off "${nginx_h3_mode}"
    run_metrics_mode_loads_for_host nginx nginx basic "${nginx_h3_mode}"
    run_metrics_mode_loads_for_host nginx nginx detailed "${nginx_h3_mode}"
  fi

  if has_comparator oxibelt; then
    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt --metrics-disabled
    run_metrics_mode_loads_for_host oxibelt oxibelt off required

    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
    run_metrics_mode_loads_for_host oxibelt oxibelt basic required

    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt --detailed-hot-path-diagnostics
    run_metrics_mode_loads_for_host oxibelt oxibelt detailed required
  fi
}

run_all_serving_types() {
  if has_comparator oxibelt; then
    start_oxibelt "${oxibelt_baseline_scenario}" oxibelt
    run_common_loads oxibelt oxibelt required
    run_external_benchmarks_for_comparator oxibelt oxibelt required
    run_static_loads oxibelt oxibelt required
    assert_oxibelt_tcp_baseline
    run_oxibelt_h2_split_loads
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
    nginx_h3_mode="$(resolve_nginx_h3_mode)"
    run_common_loads nginx nginx "${nginx_h3_mode}"
    run_external_benchmarks_for_comparator nginx nginx "${nginx_h3_mode}"
    run_handshake "nginx-tls-handshake-h2" h2 nginx
    run_static_loads nginx nginx "${nginx_h3_mode}"
  fi

  if has_comparator caddy; then
    start_caddy
    run_common_loads caddy caddy required
    run_external_benchmarks_for_comparator caddy caddy required
    run_handshake "caddy-tls-handshake-h2" h2 caddy
    run_static_loads caddy caddy required
  fi

  if has_comparator openresty; then
    start_openresty
    run_common_loads openresty openresty required
    run_external_benchmarks_for_comparator openresty openresty required
    run_handshake "openresty-tls-handshake-h2" h2 openresty
    run_static_loads openresty openresty required
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
  if [[ -s "${external_results_jsonl}" ]]; then
    jq -s '.' "${external_results_jsonl}" >"${external_results_json}"
  else
    printf '[]\n' >"${external_results_json}"
  fi
  if [[ -s "${profile_results_jsonl}" ]]; then
    jq -s '.' "${profile_results_jsonl}" >"${profile_results_json}"
  else
    printf '[]\n' >"${profile_results_json}"
  fi
  {
    echo
    echo "Artifacts:"
    echo
    echo "- results.json"
    echo "- external-results.json"
    echo "- profile-results.json"
    echo "- docker-stats.jsonl"
    echo "- logs/"
    echo "- probe-logs/"
    echo "- profiles/cpu/"
    echo "- profiles/memory/"
    echo "- external-h2load/"
    echo "- external-oha/"
    echo "- external-wrk/"
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
- nginx HTTP/3 mode: \`${nginx_h3_mode_override}\`
- OxiBelt baseline fixture: \`${oxibelt_baseline_scenario}\`
- OxiBelt aggressive fixture: \`${oxibelt_aggressive_scenario}\`
- OxiBelt handshake fixture: \`${oxibelt_handshake_scenario}\`
- Pool experiment caps: \`${pool_experiment_caps}\`
- Pool experiment concurrency presets: \`${pool_experiment_concurrency_presets}\`
- Docker command: \`${docker_command}\`
- OxiBelt AMD64 target CPU: \`${amd64_target_cpu}\`
- Perf probe image: \`${perf_probe_image}\`
- External benchmarks: \`${external_benchmarks}\`
- External benchmark tools: \`${external_benchmark_tools}\`
- External benchmark image: \`${external_benchmark_image}\`
- External benchmark gate mode: \`${external_benchmark_gate_mode}\`
- Diagnostic profiles: \`${diagnostic_profiles}\`
- Diagnostic profile mode: \`${diagnostic_profile_mode}\`
- Diagnostic profile event: \`${diagnostic_profile_event}\`
- Diagnostic profile frequency: \`${diagnostic_profile_frequency}\`
- Diagnostic profile gate mode: \`${diagnostic_profile_gate_mode}\`
- Duration: \`${duration_seconds}s\`
- Warmup: \`${warmup_seconds}s\`
- Concurrency: \`${concurrency}\`
- Profile label: \`${profile_label:-none}\`

| Scenario | Type | Protocol | Result | Notes |
| --- | --- | --- | --- | --- |
EOF

docker network create "${network_name}" >/dev/null

build_perf_probe_image
build_external_benchmark_image

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

start_perf_upstreams

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
  remote-signer)
    run_remote_signer_group
    ;;
  pool-concurrency)
    run_pool_concurrency_group
    ;;
  runtime-direct-h1)
    run_runtime_direct_h1_group
    ;;
  metrics-mode)
    run_metrics_mode_group
    ;;
  oxibelt-aggressive-long-run)
    run_oxibelt_aggressive_long_run
    ;;
esac

flush_external_h2load_h3_zero_failures
stop_active_proxy
collect_logs
finalize_results
flush_diagnostic_profile_warnings
copy_artifacts

echo "Docker performance profile ${profile} serving type ${serving_type} completed"
echo "Summary: ${summary_md}"
