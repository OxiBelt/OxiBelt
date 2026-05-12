#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tests/scripts/run-proxy-performance.sh --profile smoke|benchmark|soak [--comparators oxibelt,nginx,caddy]

Environment:
  OXIBELT_DOCKER_IMAGE             OxiBelt image to test; built locally when unset
  OXIBELT_NGINX_IMAGE              nginx comparator image (default: nginx:mainline-alpine)
  OXIBELT_CADDY_IMAGE              Caddy comparator image (default: caddy:2-alpine)
  OXIBELT_PERF_DURATION_SECONDS    load duration override
  OXIBELT_PERF_WARMUP_SECONDS      warmup duration override
  OXIBELT_PERF_CONCURRENCY         load concurrency override
  OXIBELT_PERF_SOAK_SECONDS        soak duration override
  OXIBELT_PERF_MAX_P99_MS          sanity ceiling for load p99 latency
  OXIBELT_TEST_ARTIFACT_DIR        copy summary, results, logs, configs, and stats here
  KEEP_TEST_ARTIFACTS=1            keep tests/.tmp performance work directory
EOF
}

profile="smoke"
comparators="oxibelt,nginx,caddy"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --profile)
      profile="${2:-}"
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

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
fixture_root="${repo_root}/tests/fixtures/oxibelt-docker-performance"
run_id="$(date +%s)-$$-${RANDOM}"
work_dir="${repo_root}/tests/.tmp/performance-${run_id}"
logs_dir="${work_dir}/logs"
configs_dir="${work_dir}/configs"
tls_dir="${work_dir}/proxy-tls"
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

mkdir -p "${logs_dir}" "${configs_dir}" "${tls_dir}"
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
  chmod 0644 "${tls_dir}/fullchain.pem" "${tls_dir}/privkey.pem"
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
  local output status json
  docker create \
    --name "${probe_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    "${perf_probe_image}" \
    "$@" >/dev/null
  docker cp "${tls_dir}/fullchain.pem" "${probe_container}:/tls/proxy-ca.pem"

  status=0
  output="$(docker start -a "${probe_container}" 2>&1)" || status=$?
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
  local label type protocol skipped requests rps p99 errors
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
  p99="$(jq -r '.p99_ms // 0' <<<"${json}")"
  errors="$(jq -r '.errors // 0' <<<"${json}")"
  printf '| `%s` | `%s` | `%s` | %s req, %.2f/sec, p99 %.2f ms | errors=%s |\n' \
    "${label}" "${type}" "${protocol}" "${requests}" "${rps}" "${p99}" "${errors}" >>"${summary_md}"
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
    fail_with_diagnostics "performance probe reported request errors: $(jq -r '.label' <<<"${json}")"
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
  local json
  json="$(run_probe_json load \
    --label "${label}" \
    --protocol "${protocol}" \
    --host "${host}" \
    --port 8443 \
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

run_handshake() {
  local label="$1"
  local protocol="$2"
  local host="$3"
  local json
  json="$(run_probe_json handshake \
    --label "${label}" \
    --protocol "${protocol}" \
    --host "${host}" \
    --port 8443 \
    --server-name proxy \
    --ca-cert /tls/proxy-ca.pem \
    --duration-seconds "${duration_seconds}" \
    --concurrency "${concurrency}")"
  append_result "${json}"
  assert_result "${json}"
  sample_stats "${label}"
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
  local supports_h3="$3"
  run_load "${comparator}-h1-keepalive" h1 "${host}" "/perf/h1?body=ok" "${duration_seconds}" "${concurrency}"
  run_load "${comparator}-h2" h2 "${host}" "/perf/h2?body=ok" "${duration_seconds}" "${concurrency}"
  if [[ "${supports_h3}" == "1" ]]; then
    run_load "${comparator}-h3" h3 "${host}" "/perf/h3?body=ok" "${duration_seconds}" "${concurrency}"
  else
    record_skip "${comparator}-h3" load h3 "HTTP/3 is not available for this comparator image"
  fi
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

  start_oxibelt cache oxibelt
  run_load "oxibelt-cache-miss" h2 oxibelt "/perf/cache-miss?body_repeat=4096&cache_control=no-store" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-cache-hit" h2 oxibelt "/perf/cache-hit?body_repeat=4096&cache_control=public" "${duration_seconds}" "${concurrency}"
  sleep 2
  run_load "oxibelt-cache-revalidate" h2 oxibelt "/perf/cache-revalidate?body_repeat=4096&cache_control=public-max-age-1&etag=perf" "${duration_seconds}" "${concurrency}"
  run_load "oxibelt-cache-stale" h2 oxibelt "/perf/cache-stale?body_repeat=4096&cache_control=public-stale-revalidate" "${duration_seconds}" "${concurrency}"
}

run_oxibelt_soak_and_stress() {
  start_oxibelt baseline oxibelt
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
  start_oxibelt baseline oxibelt
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
    echo "- configs/"
  } >>"${summary_md}"
}

generate_tls

cat >"${summary_md}" <<EOF
# OxiBelt Docker Performance (${profile})

- Run id: \`${run_id}\`
- Comparators: \`${comparators}\`
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

if has_comparator oxibelt; then
  start_oxibelt baseline oxibelt
  run_common_loads oxibelt oxibelt 1
  run_handshake "oxibelt-tls-handshake-h2" h2 oxibelt
  if [[ "${profile}" == "smoke" ]]; then
    run_load "oxibelt-smoke-soak" h1 oxibelt "/perf/smoke-soak?body=ok" "${soak_seconds}" "${concurrency}"
  fi
fi

if has_comparator nginx; then
  start_nginx
  run_common_loads nginx nginx "${nginx_h3_supported}"
fi

if has_comparator caddy; then
  start_caddy
  run_common_loads caddy caddy 1
fi

if has_comparator oxibelt && [[ "${profile}" == "benchmark" || "${profile}" == "soak" ]]; then
  run_oxibelt_specific_benchmarks
fi

if has_comparator oxibelt && [[ "${profile}" == "benchmark" ]]; then
  run_oxibelt_soak_and_stress
elif has_comparator oxibelt && [[ "${profile}" == "soak" ]]; then
  run_manual_soak_presets
  run_oxibelt_soak_and_stress
fi

stop_active_proxy
collect_logs
finalize_results
copy_artifacts

echo "Docker performance profile ${profile} completed"
echo "Summary: ${summary_md}"
