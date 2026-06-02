#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <category> <case>" >&2
}

category="${1:-}"
case_name="${2:-}"
if [[ -z "${category}" || -z "${case_name}" ]]; then
  usage
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
run_id="$(date +%s)-$$-${RANDOM}"
work_dir="${repo_root}/tests/.tmp/matrix-${category}-${case_name}-${run_id}"
case_dir="${work_dir}/case"
cert_dir="${work_dir}/cert"
proxy_cert_dir="${work_dir}/proxy-cert"
upstream_tls_dir="${work_dir}/upstream-tls"
postgres_tls_dir="${work_dir}/postgres-tls"
logs_dir="${work_dir}/logs"
network_name="oxibelt-matrix-${run_id}"
mock_image="${OXIBELT_MOCK_UPSTREAM_IMAGE:-oxibelt/mock-upstream:${run_id}}"
mock_dns_image="${OXIBELT_MOCK_DNS_IMAGE:-oxibelt/mock-dns:${run_id}}"
mock_kubernetes_image="${OXIBELT_MOCK_KUBERNETES_IMAGE:-oxibelt/mock-kubernetes:${run_id}}"
pq_probe_image="${OXIBELT_PQ_PROBE_IMAGE:-oxibelt/pq-probe:${run_id}}"
protocol_probe_image="${OXIBELT_PROTOCOL_PROBE_IMAGE:-oxibelt/protocol-probe:${run_id}}"
postgres_image="${OXIBELT_POSTGRES_IMAGE:-oxibelt/postgres:${run_id}}"
redis_image="${OXIBELT_REDIS_IMAGE:-valkey/valkey:8-alpine}"
proxy_image="${OXIBELT_DOCKER_IMAGE:-oxibelt/proxy-matrix:${run_id}}"
require_preloaded_helper_images="${OXIBELT_REQUIRE_PRELOADED_HELPER_IMAGES:-0}"
remove_mock_image=0
remove_mock_dns_image=0
remove_mock_kubernetes_image=0
remove_pq_probe_image=0
remove_protocol_probe_image=0
remove_postgres_image=0
remove_proxy_image=0
if [[ -z "${OXIBELT_MOCK_UPSTREAM_IMAGE:-}" ]]; then
  remove_mock_image=1
fi
if [[ -z "${OXIBELT_MOCK_DNS_IMAGE:-}" ]]; then
  remove_mock_dns_image=1
fi
if [[ -z "${OXIBELT_MOCK_KUBERNETES_IMAGE:-}" ]]; then
  remove_mock_kubernetes_image=1
fi
if [[ -z "${OXIBELT_PQ_PROBE_IMAGE:-}" ]]; then
  remove_pq_probe_image=1
fi
if [[ -z "${OXIBELT_PROTOCOL_PROBE_IMAGE:-}" ]]; then
  remove_protocol_probe_image=1
fi
if [[ -z "${OXIBELT_POSTGRES_IMAGE:-}" ]]; then
  remove_postgres_image=1
fi
proxy_container="oxibelt-proxy-${run_id}"
proxy_b_container="oxibelt-proxy-b-${run_id}"
http_container="oxibelt-http-${run_id}"
https_container="oxibelt-https-${run_id}"
alt_container="oxibelt-alt-${run_id}"
h2_container="oxibelt-h2-${run_id}"
h2c_container="oxibelt-h2c-${run_id}"
h1_stall_container="oxibelt-h1-stall-${run_id}"
h3_container="oxibelt-h3-${run_id}"
webtransport_container="oxibelt-webtransport-${run_id}"
websocket_container="oxibelt-websocket-${run_id}"
turn_udp_container="oxibelt-turn-udp-${run_id}"
turn_tcp_container="oxibelt-turn-tcp-${run_id}"
turn_tls_container="oxibelt-turn-tls-${run_id}"
dns_container="oxibelt-dns-${run_id}"
kubernetes_container="oxibelt-kubernetes-${run_id}"
postgres_container="oxibelt-postgres-${run_id}"
redis_container="oxibelt-redis-${run_id}"
remote_signer_container="oxibelt-keysigner-${run_id}"
remote_signer_socket_volume="oxibelt-keysigner-sock-${run_id}"
test_label="oxibelt.test.run=${run_id}"

cleanup() {
  docker ps -aq --filter "label=${test_label}" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "${network_name}" >/dev/null 2>&1 || true
  docker volume rm "${remote_signer_socket_volume}" >/dev/null 2>&1 || true
  if [[ "${remove_mock_image}" == "1" ]]; then
    docker rmi -f "${mock_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${remove_mock_dns_image}" == "1" ]]; then
    docker rmi -f "${mock_dns_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${remove_mock_kubernetes_image}" == "1" ]]; then
    docker rmi -f "${mock_kubernetes_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${remove_pq_probe_image}" == "1" ]]; then
    docker rmi -f "${pq_probe_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${remove_protocol_probe_image}" == "1" ]]; then
    docker rmi -f "${protocol_probe_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${remove_postgres_image}" == "1" ]]; then
    docker rmi -f "${postgres_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${remove_proxy_image}" == "1" ]]; then
    docker rmi -f "${proxy_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${KEEP_TEST_ARTIFACTS:-0}" != "1" ]]; then
    rm -rf "${work_dir}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "${case_dir}" "${cert_dir}" "${proxy_cert_dir}" "${upstream_tls_dir}" "${postgres_tls_dir}" "${logs_dir}"

unique_docker_container_name() {
  local prefix="$1"
  local attempt="${2:-0}"

  printf '%s-%s-%s-%s-%s-%s' \
    "${prefix}" \
    "${run_id}" \
    "${BASHPID:-$$}" \
    "${attempt}" \
    "${RANDOM}" \
    "$(date +%s%N)"
}

container_stderr_log() {
  local container_name="$1"
  printf '%s/%s.stderr.log' "${logs_dir}" "${container_name}"
}

docker_start_stdout_only() {
  local container_name="$1"
  mkdir -p "${logs_dir}"
  docker start -a "${container_name}" 2>"$(container_stderr_log "${container_name}")"
}

append_container_stderr() {
  local container_name="$1"
  local stderr_log
  stderr_log="$(container_stderr_log "${container_name}")"
  if [[ -s "${stderr_log}" ]]; then
    cat "${stderr_log}" >&2
  fi
}

docker_build_with_retry() {
  local attempt=1
  local max_attempts=3
  local status=0

  while ((attempt <= max_attempts)); do
    if docker build "$@"; then
      return 0
    fi
    status=$?
    if ((attempt == max_attempts)); then
      return "${status}"
    fi
    echo "docker build failed on attempt ${attempt}/${max_attempts}; retrying" >&2
    sleep 5
    attempt=$((attempt + 1))
  done
}

require_preloaded_helper_image() {
  local image="$1"
  if [[ "${require_preloaded_helper_images}" != "1" ]]; then
    return 0
  fi
  if ! docker image inspect "${image}" >/dev/null 2>&1; then
    echo "required preloaded Docker integration helper image is missing: ${image}" >&2
    echo "load the oxibelt-docker-integration-helper-images artifact or unset OXIBELT_REQUIRE_PRELOADED_HELPER_IMAGES" >&2
    exit 1
  fi
}

ensure_helper_image() {
  local image="$1"
  local remove_flag_name="$2"
  local dockerfile="$3"
  local context="$4"

  require_preloaded_helper_image "${image}"
  if [[ "${require_preloaded_helper_images}" == "1" || "${!remove_flag_name}" != "1" ]]; then
    return 0
  fi

  docker_build_with_retry \
    -t "${image}" \
    -f "${dockerfile}" \
    "${context}" >/dev/null
}

cargo run --quiet --locked -p oxibelt --bin oxibelt-docker-integration-matrix -- \
  materialize \
  --suite docker \
  --category "${category}" \
  --case "${case_name}" \
  --output "${case_dir}"

# shellcheck source=/dev/null
source "${case_dir}/manifest.env"

collect_diagnostics() {
  mkdir -p "${logs_dir}"
  docker logs "${proxy_container}" >"${logs_dir}/proxy.log" 2>&1 || true
  docker logs "${proxy_b_container}" >"${logs_dir}/proxy-b.log" 2>&1 || true
  docker logs "${http_container}" >"${logs_dir}/mock-http.log" 2>&1 || true
  docker logs "${https_container}" >"${logs_dir}/mock-https.log" 2>&1 || true
  docker logs "${alt_container}" >"${logs_dir}/mock-alt.log" 2>&1 || true
  docker logs "${h2_container}" >"${logs_dir}/mock-h2.log" 2>&1 || true
  docker logs "${h2c_container}" >"${logs_dir}/mock-h2c.log" 2>&1 || true
  docker logs "${h1_stall_container}" >"${logs_dir}/mock-h1-stall.log" 2>&1 || true
  docker logs "${h3_container}" >"${logs_dir}/mock-h3.log" 2>&1 || true
  docker logs "${webtransport_container}" >"${logs_dir}/mock-webtransport.log" 2>&1 || true
  docker logs "${websocket_container}" >"${logs_dir}/mock-websocket.log" 2>&1 || true
  docker logs "${turn_udp_container}" >"${logs_dir}/mock-turn-udp.log" 2>&1 || true
  docker logs "${turn_tcp_container}" >"${logs_dir}/mock-turn-tcp.log" 2>&1 || true
  docker logs "${turn_tls_container}" >"${logs_dir}/mock-turn-tls.log" 2>&1 || true
  docker logs "${dns_container}" >"${logs_dir}/mock-dns.log" 2>&1 || true
  docker logs "${kubernetes_container}" >"${logs_dir}/mock-kubernetes.log" 2>&1 || true
  docker logs "${postgres_container}" >"${logs_dir}/postgres.log" 2>&1 || true
  docker logs "${redis_container}" >"${logs_dir}/redis.log" 2>&1 || true
  docker logs "${remote_signer_container}" >"${logs_dir}/remote-signer.log" 2>&1 || true

  if [[ -n "${OXIBELT_TEST_ARTIFACT_DIR:-}" ]]; then
    mkdir -p "${OXIBELT_TEST_ARTIFACT_DIR}"
    cp -R "${logs_dir}/." "${OXIBELT_TEST_ARTIFACT_DIR}/" 2>/dev/null || true
    cp -R "${case_dir}" "${OXIBELT_TEST_ARTIFACT_DIR}/case" 2>/dev/null || true
  fi
}

fail_with_diagnostics() {
  echo "$1" >&2
  collect_diagnostics
  exit 1
}

assert_response_jq() {
  local response="$1"
  local filter="$2"
  if ! jq -e "${filter}" <<<"${response}" >/dev/null; then
    echo "Response assertion failed: ${filter}" >&2
    echo "${response}" >&2
    fail_with_diagnostics "response assertion failed"
  fi
}

assert_body_jq() {
  local response="$1"
  local filter="$2"
  if ! jq -e ".body | fromjson | ${filter}" <<<"${response}" >/dev/null; then
    echo "Response body assertion failed: ${filter}" >&2
    echo "${response}" >&2
    fail_with_diagnostics "response body assertion failed"
  fi
}

response_status_matches() {
  local response="$1"
  local expected_statuses="$2"
  local actual_status=""
  actual_status="$(jq -r '.status // empty' <<<"${response}" 2>/dev/null || true)"
  if [[ -z "${actual_status}" ]]; then
    return 1
  fi

  local expected=""
  local -a expected_status_values=()
  IFS=',' read -ra expected_status_values <<<"${expected_statuses}"
  for expected in "${expected_status_values[@]}"; do
    if [[ "${actual_status}" == "${expected}" ]]; then
      return 0
    fi
  done
  return 1
}

client_request() {
  client_request_on_port 8443 "$1" "$2" "$3" "GET" ""
}

client_request_to_target() {
  client_request_with_headers_to_target "$1" 8443 "$2" "$3" "$4" "GET" ""
}

client_request_with_sni() {
  client_request_with_sni_and_ca "${cert_dir}/fullchain.pem" "$1" "$2" "$3" "$4"
}

sni_forward_tls_request() {
  client_request_with_sni_and_ca "${upstream_tls_dir}/ca.pem" "$1" "$1" "$2" "$3"
}

client_request_with_sni_and_ca() {
  local ca_file="$1"
  local server_name="$2"
  local host="$3"
  local path="$4"
  local expect_status="$5"
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-sni-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --entrypoint python \
      "${mock_image}" \
      /opt/mock_upstream/client.py \
      --target-host proxy \
      --server-name "${server_name}" \
      --path "${path}" \
      --host "${host}" \
      --port 8443 \
      --method GET \
      --body "" \
      --ca-file /tmp/sni-ca.pem \
      --dump-response-json \
      --expect-status "${expect_status}" >/dev/null
    docker cp "${ca_file}" "${client_container}:/tmp/sni-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "SNI client request for ${server_name} failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "SNI client request did not reach expected status ${expect_status}"
}

client_request_on_port() {
  local port="$1"
  shift
  client_request_with_headers_on_port "${port}" "$1" "$2" "$3" "GET" ""
}

client_request_with_headers() {
  client_request_with_headers_on_port 8443 "$@"
}

client_request_with_headers_to_target() {
  local target_host="$1"
  local proxy_port="$2"
  shift 2
  local host="$1"
  local path="$2"
  local expect_status="$3"
  local method="$4"
  local body="$5"
  shift 5
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done
  local expect_args=()
  if [[ "${expect_status}" != *,* ]]; then
    expect_args+=(--expect-status "${expect_status}")
  fi

  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --entrypoint python \
      "${mock_image}" \
      /opt/mock_upstream/client.py \
      --target-host "${target_host}" \
      --path "${path}" \
      --host "${host}" \
      --port "${proxy_port}" \
      --method "${method}" \
      --body "${body}" \
      --ca-file /tmp/proxy-ca.pem \
      --dump-response-json \
      "${expect_args[@]}" \
      "${header_args[@]}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      if [[ "${expect_status}" == *,* ]]; then
        if response_status_matches "${output}" "${expect_status}"; then
          printf '%s' "${output}"
          return 0
        fi
      else
        printf '%s' "${output}"
        return 0
      fi
      sleep 1
      continue
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    if [[ "${expect_status}" == *,* ]] && response_status_matches "${output}" "${expect_status}"; then
      printf '%s' "${output}"
      return 0
    fi
    sleep 1
  done

  echo "client request to ${target_host} failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "client request to ${target_host} did not reach expected status ${expect_status}"
}

client_request_with_headers_on_port() {
  local proxy_port="$1"
  shift
  local host="$1"
  local path="$2"
  local expect_status="$3"
  local method="$4"
  local body="$5"
  shift 5
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --entrypoint python \
      "${mock_image}" \
      /opt/mock_upstream/client.py \
      --path "${path}" \
      --host "${host}" \
      --port "${proxy_port}" \
      --method "${method}" \
      --body "${body}" \
      --ca-file /tmp/proxy-ca.pem \
      --dump-response-json \
      --expect-status "${expect_status}" \
      "${header_args[@]}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "client request failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "client request did not reach expected status ${expect_status}"
}

probe_client_request_with_headers() {
  local host="$1"
  local path="$2"
  local method="$3"
  local body="$4"
  shift 4
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  local output=""
  local status=0
  local client_container=""

  client_container="$(unique_docker_container_name "oxibelt-probe-client")"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --path "${path}" \
    --host "${host}" \
    --port 8443 \
    --method "${method}" \
    --body "${body}" \
    --ca-file /tmp/proxy-ca.pem \
    --dump-response-json \
    "${header_args[@]}" >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  output="$(docker start -a "${client_container}" 2>&1)" || status=$?
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  printf '%s' "${output}"
  return "${status}"
}

slow_body_client_request() {
  local host="$1"
  local path="$2"
  local expect_status="$3"
  local method="$4"
  local body="$5"
  local delay_ms="$6"
  shift 6
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  local output=""
  local status=0
  local client_container=""

  client_container="$(unique_docker_container_name "oxibelt-slow-body-client")"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --path "${path}" \
    --host "${host}" \
    --port 8443 \
    --method "${method}" \
    --body "${body}" \
    --slow-body-delay-ms "${delay_ms}" \
    --ca-file /tmp/proxy-ca.pem \
    --dump-response-json \
    --expect-status "${expect_status}" \
    --timeout 10 \
    "${header_args[@]}" >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  if output="$(docker_start_stdout_only "${client_container}")"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    printf '%s' "${output}"
    return 0
  fi
  status=$?
  append_container_stderr "${client_container}"
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  echo "slow body client request failed with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "slow body request did not reach expected status ${expect_status}"
}

split_body_client_request() {
  local host="$1"
  local path="$2"
  local expect_status="$3"
  local method="$4"
  local body="$5"
  local split_at="$6"
  local split_delay_ms="$7"
  shift 7
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  local output=""
  local status=0
  local client_container=""

  client_container="$(unique_docker_container_name "oxibelt-split-body-client")"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --path "${path}" \
    --host "${host}" \
    --port 8443 \
    --method "${method}" \
    --body "${body}" \
    --body-split-at "${split_at}" \
    --body-split-delay-ms "${split_delay_ms}" \
    --ca-file /tmp/proxy-ca.pem \
    --dump-response-json \
    --expect-status "${expect_status}" \
    --timeout 10 \
    "${header_args[@]}" >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  if output="$(docker_start_stdout_only "${client_container}")"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    printf '%s' "${output}"
    return 0
  fi
  status=$?
  append_container_stderr "${client_container}"
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  echo "split body client request failed with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "split body request did not reach expected status ${expect_status}"
}

chunked_body_client_request() {
  local host="$1"
  local path="$2"
  local expect_status="$3"
  local method="$4"
  local body="$5"
  shift 5
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  local output=""
  local status=0
  local client_container=""

  client_container="$(unique_docker_container_name "oxibelt-chunked-body-client")"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --path "${path}" \
    --host "${host}" \
    --port 8443 \
    --method "${method}" \
    --body "${body}" \
    --chunked-body \
    --ca-file /tmp/proxy-ca.pem \
    --dump-response-json \
    --expect-status "${expect_status}" \
    --timeout 10 \
    "${header_args[@]}" >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  if output="$(docker_start_stdout_only "${client_container}")"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    printf '%s' "${output}"
    return 0
  fi
  status=$?
  append_container_stderr "${client_container}"
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  echo "chunked body client request failed with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "chunked body request did not reach expected status ${expect_status}"
}

plain_client_request() {
  plain_client_request_on_port 8080 "$1" "$2" "$3" "GET" ""
}

plain_client_request_to_target() {
  plain_client_request_with_headers_to_target "$1" 8080 "$2" "$3" "$4" "GET" ""
}

plain_client_request_on_port() {
  local port="$1"
  shift
  plain_client_request_with_headers_on_port "${port}" "$1" "$2" "$3" "GET" ""
}

plain_client_request_with_headers_on_port() {
  local proxy_port="$1"
  shift
  local host="$1"
  local path="$2"
  local expect_status="$3"
  local method="$4"
  local body="$5"
  shift 5
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-plain-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --entrypoint python \
      "${mock_image}" \
      /opt/mock_upstream/client.py \
      --scheme http \
      --path "${path}" \
      --host "${host}" \
      --port "${proxy_port}" \
      --method "${method}" \
      --body "${body}" \
      --dump-response-json \
      --expect-status "${expect_status}" \
      "${header_args[@]}" >/dev/null

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "plain client request failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "plain client request did not reach expected status ${expect_status}"
}

plain_client_request_with_headers_to_target() {
  local target_host="$1"
  local proxy_port="$2"
  shift 2
  local host="$1"
  local path="$2"
  local expect_status="$3"
  local method="$4"
  local body="$5"
  shift 5
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-plain-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --entrypoint python \
      "${mock_image}" \
      /opt/mock_upstream/client.py \
      --target-host "${target_host}" \
      --scheme http \
      --path "${path}" \
      --host "${host}" \
      --port "${proxy_port}" \
      --method "${method}" \
      --body "${body}" \
      --dump-response-json \
      --expect-status "${expect_status}" \
      "${header_args[@]}" >/dev/null

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "plain client request to ${target_host} failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "plain client request to ${target_host} did not reach expected status ${expect_status}"
}

proxy_protocol_client_request() {
  local proxy_line="$1"
  local host="$2"
  local path="$3"
  local expect_status="$4"
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-proxy-protocol-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --entrypoint python \
      "${mock_image}" \
      /opt/mock_upstream/client.py \
      --scheme https \
      --path "${path}" \
      --host "${host}" \
      --port 8443 \
      --method GET \
      --body "" \
      --ca-file /tmp/proxy-ca.pem \
      --proxy-protocol-line "${proxy_line}" \
      --dump-response-json \
      --expect-status "${expect_status}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "PROXY protocol client request failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "PROXY protocol request did not reach expected status ${expect_status}"
}

probe_proxy_protocol_client_request() {
  local proxy_line="$1"
  local host="$2"
  local path="$3"
  local output=""
  local status=0
  local client_container
  client_container="$(unique_docker_container_name "oxibelt-proxy-protocol-probe")"

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --scheme https \
    --path "${path}" \
    --host "${host}" \
    --port 8443 \
    --method GET \
    --body "" \
    --ca-file /tmp/proxy-ca.pem \
    --proxy-protocol-line "${proxy_line}" \
    --dump-response-json >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  output="$(docker start -a "${client_container}" 2>&1)" || status=$?
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  printf '%s' "${output}"
  return "${status}"
}

start_holding_client_request_with_headers() {
  local target_host="$1"
  local proxy_port="$2"
  local scheme="$3"
  local proxy_line="$4"
  local host="$5"
  local path="$6"
  local expect_status="$7"
  local hold_ms="$8"
  shift 8
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  HOLDING_CLIENT_CONTAINER="$(unique_docker_container_name "oxibelt-holding-client")"
  HOLDING_CLIENT_LOG="${logs_dir}/${HOLDING_CLIENT_CONTAINER}.log"
  local proxy_args=()
  if [[ -n "${proxy_line}" ]]; then
    proxy_args+=(--proxy-protocol-line "${proxy_line}")
  fi
  local ca_args=()
  if [[ "${scheme}" == "https" ]]; then
    ca_args+=(--ca-file /tmp/proxy-ca.pem)
  fi

  docker create \
    --name "${HOLDING_CLIENT_CONTAINER}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --target-host "${target_host}" \
    --scheme "${scheme}" \
    --path "${path}" \
    --host "${host}" \
    --port "${proxy_port}" \
    --method GET \
    --body "" \
    --dump-response-json \
    --expect-status "${expect_status}" \
    --connection keep-alive \
    --hold-after-headers-ms "${hold_ms}" \
    --timeout 15 \
    "${ca_args[@]}" \
    "${proxy_args[@]}" \
    "${header_args[@]}" >/dev/null
  if [[ "${scheme}" == "https" ]]; then
    docker cp "${cert_dir}/fullchain.pem" "${HOLDING_CLIENT_CONTAINER}:/tmp/proxy-ca.pem"
  fi
  docker start -a "${HOLDING_CLIENT_CONTAINER}" >"${HOLDING_CLIENT_LOG}" 2>&1 &
  HOLDING_CLIENT_PID=$!
  sleep 1
}

wait_holding_client() {
  if ! wait "${HOLDING_CLIENT_PID}"; then
    cat "${HOLDING_CLIENT_LOG}" >&2 || true
    fail_with_diagnostics "holding client request failed"
  fi
  docker rm -f "${HOLDING_CLIENT_CONTAINER}" >/dev/null 2>&1 || true
}

start_holding_upgrade_client_request_with_headers() {
  local host="$1"
  local path="$2"
  local token="$3"
  local body="$4"
  local expect_status="$5"
  local hold_ms="$6"
  shift 6
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  HOLDING_CLIENT_CONTAINER="$(unique_docker_container_name "oxibelt-holding-upgrade-client")"
  HOLDING_CLIENT_LOG="${logs_dir}/${HOLDING_CLIENT_CONTAINER}.log"
  docker create \
    --name "${HOLDING_CLIENT_CONTAINER}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --scheme https \
    --path "${path}" \
    --host "${host}" \
    --port 8443 \
    --method GET \
    --body "${body}" \
    --ca-file /tmp/proxy-ca.pem \
    --upgrade-token "${token}" \
    --dump-response-json \
    --expect-status "${expect_status}" \
    --hold-after-headers-ms "${hold_ms}" \
    --timeout 15 \
    "${header_args[@]}" >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${HOLDING_CLIENT_CONTAINER}:/tmp/proxy-ca.pem"

  docker start -a "${HOLDING_CLIENT_CONTAINER}" >"${HOLDING_CLIENT_LOG}" 2>&1 &
  HOLDING_CLIENT_PID=$!
  sleep 1
}

start_holding_connect_tunnel_request_with_headers() {
  local host="$1"
  local tunneled_path="$2"
  local expect_status="$3"
  local hold_ms="$4"
  shift 4
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  HOLDING_CLIENT_CONTAINER="$(unique_docker_container_name "oxibelt-holding-connect-client")"
  HOLDING_CLIENT_LOG="${logs_dir}/${HOLDING_CLIENT_CONTAINER}.log"
  docker create \
    --name "${HOLDING_CLIENT_CONTAINER}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --scheme https \
    --path "${tunneled_path}" \
    --host "${host}" \
    --port 8443 \
    --method GET \
    --body "" \
    --ca-file /tmp/proxy-ca.pem \
    --connect-tunnel \
    --dump-response-json \
    --expect-status "${expect_status}" \
    --hold-after-headers-ms "${hold_ms}" \
    --timeout 15 \
    "${header_args[@]}" >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${HOLDING_CLIENT_CONTAINER}:/tmp/proxy-ca.pem"

  docker start -a "${HOLDING_CLIENT_CONTAINER}" >"${HOLDING_CLIENT_LOG}" 2>&1 &
  HOLDING_CLIENT_PID=$!
  sleep 1
}

upgrade_client_request() {
  upgrade_client_request_with_headers "$1" "$2" "$3" "$4" "$5"
}

upgrade_client_request_with_headers() {
  local host="$1"
  local path="$2"
  local token="$3"
  local body="$4"
  local expect_status="$5"
  shift 5
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-upgrade-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --entrypoint python \
      "${mock_image}" \
      /opt/mock_upstream/client.py \
      --scheme https \
      --path "${path}" \
      --host "${host}" \
      --port 8443 \
      --method GET \
      --body "${body}" \
      --ca-file /tmp/proxy-ca.pem \
      --upgrade-token "${token}" \
      --dump-response-json \
      --expect-status "${expect_status}" \
      "${header_args[@]}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "upgrade client request failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "upgrade request did not reach expected status ${expect_status}"
}

connect_tunnel_request() {
  connect_tunnel_request_with_headers "$1" "$2" "$3"
}

connect_tunnel_request_with_headers() {
  local host="$1"
  local tunneled_path="$2"
  local expect_status="$3"
  shift 3
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-connect-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --entrypoint python \
      "${mock_image}" \
      /opt/mock_upstream/client.py \
      --scheme https \
      --path "${tunneled_path}" \
      --host "${host}" \
      --port 8443 \
      --method GET \
      --body "" \
      --ca-file /tmp/proxy-ca.pem \
      --connect-tunnel \
      --dump-response-json \
      --expect-status "${expect_status}" \
      "${header_args[@]}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "CONNECT tunnel request failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "CONNECT tunnel did not reach expected status ${expect_status}"
}

reload_proxy() {
  docker kill --signal HUP "${proxy_container}" >/dev/null
}

protocol_probe_client() {
  local protocol="$1"
  local authority="$2"
  local path="$3"
  local expect_status="$4"
  protocol_probe_client_with_sni_and_ca "${protocol}" "proxy" "${authority}" "${path}" "${expect_status}" "${cert_dir}/fullchain.pem"
}

protocol_probe_client_with_sni_and_ca() {
  local protocol="$1"
  local server_name="$2"
  local authority="$3"
  local path="$4"
  local expect_status="$5"
  local ca_file="$6"
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 "${PROTOCOL_PROBE_ATTEMPTS:-30}"); do
    client_container="$(unique_docker_container_name "oxibelt-protocol-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      downstream \
      --protocol "${protocol}" \
      --host proxy \
      --port 8443 \
      --server-name "${server_name}" \
      --authority "${authority}" \
      --path "${path}" \
      --ca-cert /tmp/probe-ca.pem \
      --expect-status "${expect_status}" >/dev/null
    docker cp "${ca_file}" "${client_container}:/tmp/probe-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "protocol probe client failed after retries with status ${status}: protocol=${protocol} server_name=${server_name} authority=${authority} path=${path}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "protocol probe did not reach expected status ${expect_status}"
}

protocol_probe_websocket_client() {
  local authority="$1"
  local path="$2"
  local expect_status="$3"
  local payload="$4"
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 "${PROTOCOL_PROBE_ATTEMPTS:-30}"); do
    client_container="$(unique_docker_container_name "oxibelt-websocket-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      websocket-client \
      --host proxy \
      --port 8443 \
      --server-name proxy \
      --authority "${authority}" \
      --path "${path}" \
      --ca-cert /tmp/proxy-ca.pem \
      --payload "${payload}" \
      --expect-status "${expect_status}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "WebSocket protocol probe failed after retries with status ${status}: authority=${authority} path=${path}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "WebSocket protocol probe did not reach expected status ${expect_status}"
}

protocol_probe_turn_client() {
  local transport="$1"
  local port="$2"
  local auth="$3"
  local expect="$4"
  local output=""
  local status=0
  local client_container=""
  local ca_args=()

  if [[ "${transport}" == "tls" ]]; then
    ca_args=(--ca-cert /tmp/proxy-ca.pem)
  fi

  for attempt in $(seq 1 "${PROTOCOL_PROBE_ATTEMPTS:-30}"); do
    client_container="$(unique_docker_container_name "oxibelt-turn-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      turn-client \
      --transport "${transport}" \
      --host proxy \
      --port "${port}" \
      --server-name proxy \
      --username turn-user \
      --realm turn.example.test \
      --password turn-password \
      --auth "${auth}" \
      --expect "${expect}" \
      "${ca_args[@]}" >/dev/null
    if [[ "${transport}" == "tls" ]]; then
      docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"
    fi

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "TURN protocol probe failed after retries with status ${status}: transport=${transport} auth=${auth} expect=${expect}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "TURN protocol probe did not observe expected ${expect} result"
}

protocol_probe_tls_resumption_load() {
  local authority="$1"
  local path="$2"
  local connections="$3"
  local expect_resumed_min="$4"
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-tls-resumption-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      tls-resumption-load \
      --host proxy \
      --port 8443 \
      --server-name proxy \
      --authority "${authority}" \
      --path "${path}" \
      --ca-cert /tmp/proxy-ca.pem \
      --connections "${connections}" \
      --expect-resumed-min "${expect_resumed_min}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "TLS resumption probe failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "TLS resumption probe did not observe enough resumed handshakes"
}

protocol_probe_client_with_headers() {
  local protocol="$1"
  local authority="$2"
  local path="$3"
  local expect_status="$4"
  local method="$5"
  local body="$6"
  shift 6
  local output=""
  local status=0
  local client_container=""
  local header_args=()
  local header=""
  for header in "$@"; do
    header_args+=(--header "${header}")
  done

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-protocol-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      downstream \
      --protocol "${protocol}" \
      --host proxy \
      --port 8443 \
      --server-name proxy \
      --authority "${authority}" \
      --path "${path}" \
      --method "${method}" \
      --body "${body}" \
      --ca-cert /tmp/proxy-ca.pem \
      --expect-status "${expect_status}" \
      "${header_args[@]}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "protocol probe client failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "protocol probe did not reach expected status ${expect_status}"
}

protocol_probe_generated_body_request() {
  local protocol="$1"
  local authority="$2"
  local path="$3"
  local method="$4"
  local body_bytes="$5"
  local body_chunk_size="$6"
  shift 6
  local extra_args=("$@")
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-protocol-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      downstream \
      --protocol "${protocol}" \
      --host proxy \
      --port 8443 \
      --server-name proxy \
      --authority "${authority}" \
      --path "${path}" \
      --method "${method}" \
      --body-bytes "${body_bytes}" \
      --body-chunk-size "${body_chunk_size}" \
      --ca-cert /tmp/proxy-ca.pem \
      "${extra_args[@]}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "protocol probe generated-body client failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "protocol probe generated-body request failed"
}

protocol_probe_generated_body_request_expect_error() {
  local protocol="$1"
  local authority="$2"
  local path="$3"
  local method="$4"
  local body_bytes="$5"
  local body_chunk_size="$6"
  local expected_error="$7"
  shift 7
  local extra_args=("$@")
  local output=""
  local status=0
  local client_container=""
  local stderr_log=""
  local stderr_output=""

  for attempt in $(seq 1 5); do
    client_container="$(unique_docker_container_name "oxibelt-protocol-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      downstream \
      --protocol "${protocol}" \
      --host proxy \
      --port 8443 \
      --server-name proxy \
      --authority "${authority}" \
      --path "${path}" \
      --method "${method}" \
      --body-bytes "${body_bytes}" \
      --body-chunk-size "${body_chunk_size}" \
      --ca-cert /tmp/proxy-ca.pem \
      "${extra_args[@]}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      echo "${output}" >&2
      fail_with_diagnostics "protocol probe generated-body request unexpectedly succeeded"
    fi

    status=$?
    stderr_log="$(container_stderr_log "${client_container}")"
    stderr_output="$(cat "${stderr_log}" 2>/dev/null || true)"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true

    if grep -F "${expected_error}" <<<"${stderr_output}" >/dev/null; then
      return 0
    fi
    echo "${stderr_output}" >&2
    sleep 1
  done

  echo "protocol probe generated-body client failed after retries with status ${status}" >&2
  fail_with_diagnostics "protocol probe generated-body request did not fail with expected error: ${expected_error}"
}

protocol_probe_zero_length_body_delay_request() {
  local authority="$1"
  local path="$2"
  local expect_status="$3"
  local method="$4"
  local delay_ms="$5"
  shift 5
  local extra_args=("$@")
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-zero-length-protocol-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      downstream \
      --protocol h2 \
      --host proxy \
      --port 8443 \
      --server-name proxy \
      --authority "${authority}" \
      --path "${path}" \
      --method "${method}" \
      --zero-length-body-end-delay-ms "${delay_ms}" \
      --ca-cert /tmp/proxy-ca.pem \
      --expect-status "${expect_status}" \
      "${extra_args[@]}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "protocol probe zero-length delayed-body client failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "protocol probe zero-length delayed-body request failed"
}

protocol_probe_webtransport_multiplex() {
  local authority="$1"
  local path="$2"
  local sessions="$3"
  local expect_statuses="$4"
  shift 4
  local extra_args=("$@")
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-webtransport-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      webtransport-multiplex \
      --host proxy \
      --port 8443 \
      --server-name proxy \
      --authority "${authority}" \
      --path "${path}" \
      --ca-cert /tmp/proxy-ca.pem \
      --sessions "${sessions}" \
      --expect-statuses "${expect_statuses}" \
      "${extra_args[@]}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "WebTransport multiplex probe failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "WebTransport multiplex probe did not reach expected statuses ${expect_statuses}"
}

protocol_probe_admin_operation_wt_events() {
  local path="$1"
  local expect_event="$2"
  local expect_terminal_state="$3"
  local output=""
  local status=0
  local client_container=""

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-admin-wt-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      admin-operation-wt-events \
      --host proxy \
      --port 9092 \
      --path "${path}" \
      --ca-cert /tmp/proxy-ca.pem \
      --header "Authorization: Bearer matrix-admin-token" \
      --expect-event "${expect_event}" \
      --expect-terminal-state "${expect_terminal_state}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "Admin WebTransport operation event probe failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "Admin WebTransport operation event probe did not reach expected terminal state ${expect_terminal_state}"
}

postgres_query() {
  local sql="$1"
  docker exec \
    -e PGPASSWORD=oxibelt \
    "${postgres_container}" \
    psql -U oxibelt -d oxibelt -Atc "${sql}"
}

postgres_is_ready() {
  docker exec "${postgres_container}" pg_isready -h 127.0.0.1 -U oxibelt -d oxibelt >/dev/null 2>&1
}

redis_is_ready() {
  docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli ping; else redis-cli ping; fi' 2>/dev/null | grep -F PONG >/dev/null
}

run_pq_probe() {
  local group="$1"
  local container_name="oxibelt-pq-${group}-${run_id}"
  local output=""

  docker create \
    --name "${container_name}" \
    --label "${test_label}" \
    --network "${network_name}" \
    "${pq_probe_image}" \
    --host proxy \
    --port 8443 \
    --server-name proxy \
    --ca-cert /tmp/downstream-ca.pem \
    --group "${group}" >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${container_name}:/tmp/downstream-ca.pem"

  if ! output="$(docker start -a "${container_name}" 2>&1)"; then
    echo "${output}" >&2
    docker rm -f "${container_name}" >/dev/null 2>&1 || true
    fail_with_diagnostics "post-quantum probe failed for group ${group}"
  fi
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
  echo "${output}"
}

cat >"${work_dir}/upstream-ca.cnf" <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = oxibelt-matrix-upstream-root

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat >"${work_dir}/upstream-leaf.cnf" <<'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = mock-https

[req_ext]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = mock-https
DNS.2 = mock-h2
DNS.3 = mock-h3
DNS.4 = mock-webtransport
DNS.5 = sni-forward.test
DNS.6 = sni-default.test
DNS.7 = quic-forward.test
DNS.8 = mock-turn-tls
EOF

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
DNS.2 = localhost
DNS.3 = proxy-b
DNS.4 = example.test
IP.1 = 127.0.0.1
EOF

cat >"${work_dir}/postgres-ca.cnf" <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = oxibelt-matrix-postgres-root

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat >"${work_dir}/postgres-server.cnf" <<'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = mock-postgres

[req_ext]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = mock-postgres
EOF

cat >"${work_dir}/postgres-client.cnf" <<'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = oxibelt

[req_ext]
extendedKeyUsage = clientAuth
EOF

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 1 \
  -config "${work_dir}/upstream-ca.cnf" \
  -keyout "${upstream_tls_dir}/ca.key" \
  -out "${upstream_tls_dir}/ca.pem" >/dev/null 2>&1

openssl req -newkey rsa:2048 -sha256 -nodes \
  -config "${work_dir}/upstream-leaf.cnf" \
  -keyout "${upstream_tls_dir}/server.key" \
  -out "${upstream_tls_dir}/server.csr" >/dev/null 2>&1

openssl x509 -req -sha256 -days 1 \
  -in "${upstream_tls_dir}/server.csr" \
  -CA "${upstream_tls_dir}/ca.pem" \
  -CAkey "${upstream_tls_dir}/ca.key" \
  -CAcreateserial \
  -extfile "${work_dir}/upstream-leaf.cnf" \
  -extensions req_ext \
  -out "${upstream_tls_dir}/server.pem" >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 1 \
  -config "${work_dir}/downstream.cnf" \
  -keyout "${cert_dir}/privkey.pem" \
  -out "${cert_dir}/fullchain.pem" >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 1 \
  -config "${work_dir}/postgres-ca.cnf" \
  -keyout "${postgres_tls_dir}/ca.key" \
  -out "${postgres_tls_dir}/ca.pem" >/dev/null 2>&1

openssl req -newkey rsa:2048 -sha256 -nodes \
  -config "${work_dir}/postgres-server.cnf" \
  -keyout "${postgres_tls_dir}/server.key" \
  -out "${postgres_tls_dir}/server.csr" >/dev/null 2>&1

openssl x509 -req -sha256 -days 1 \
  -in "${postgres_tls_dir}/server.csr" \
  -CA "${postgres_tls_dir}/ca.pem" \
  -CAkey "${postgres_tls_dir}/ca.key" \
  -CAcreateserial \
  -extfile "${work_dir}/postgres-server.cnf" \
  -extensions req_ext \
  -out "${postgres_tls_dir}/server.pem" >/dev/null 2>&1

openssl req -newkey rsa:2048 -sha256 -nodes \
  -config "${work_dir}/postgres-client.cnf" \
  -keyout "${postgres_tls_dir}/client.key" \
  -out "${postgres_tls_dir}/client.csr" >/dev/null 2>&1

openssl x509 -req -sha256 -days 1 \
  -in "${postgres_tls_dir}/client.csr" \
  -CA "${postgres_tls_dir}/ca.pem" \
  -CAkey "${postgres_tls_dir}/ca.key" \
  -CAcreateserial \
  -extfile "${work_dir}/postgres-client.cnf" \
  -extensions req_ext \
  -out "${postgres_tls_dir}/client.pem" >/dev/null 2>&1

cp "${upstream_tls_dir}/ca.pem" "${cert_dir}/upstream-ca.pem"
cp "${postgres_tls_dir}/ca.pem" "${cert_dir}/postgres-ca.pem"
cp "${postgres_tls_dir}/client.pem" "${cert_dir}/postgres-client.pem"
cp "${postgres_tls_dir}/client.key" "${cert_dir}/postgres-client.key"
printf 'ocsp' >"${cert_dir}/ocsp.der"
printf 'not an ECHConfigList' >"${cert_dir}/invalid.echconfiglist"
chmod 644 "${cert_dir}/"* "${upstream_tls_dir}/"* "${postgres_tls_dir}/"*
chmod 600 "${postgres_tls_dir}/"*.key
cp "${cert_dir}/"* "${proxy_cert_dir}/"
if [[ "${CASE_NEED_REMOTE_SIGNER}" == "1" ]]; then
  rm -f "${proxy_cert_dir}/privkey.pem"
fi

docker network create "${network_name}" >/dev/null

if [[ "${CASE_EXPECT_START}" == "success" || "${CASE_NEED_HTTP_UPSTREAM}" == "1" || "${CASE_NEED_HTTPS_UPSTREAM}" == "1" || "${CASE_NEED_ALT_UPSTREAM}" == "1" ]]; then
  ensure_helper_image \
    "${mock_image}" \
    remove_mock_image \
    "${repo_root}/tests/docker/mock_upstream/Dockerfile" \
    "${repo_root}/tests/docker/mock_upstream"
fi

if [[ "${CASE_NEED_DNS_SERVER}" == "1" ]]; then
  ensure_helper_image \
    "${mock_dns_image}" \
    remove_mock_dns_image \
    "${repo_root}/tests/docker/mock_dns/Dockerfile" \
    "${repo_root}/tests/docker/mock_dns"
fi

if [[ "${CASE_NEED_KUBERNETES_SERVER}" == "1" ]]; then
  ensure_helper_image \
    "${mock_kubernetes_image}" \
    remove_mock_kubernetes_image \
    "${repo_root}/tests/docker/mock_kubernetes/Dockerfile" \
    "${repo_root}/tests/docker/mock_kubernetes"
fi

if [[ "${CASE_NEED_PQ_PROBE}" == "1" ]]; then
  ensure_helper_image \
    "${pq_probe_image}" \
    remove_pq_probe_image \
    "${repo_root}/tests/docker/pq_probe/Dockerfile" \
    "${repo_root}/tests/docker/pq_probe"
fi

if [[ "${CASE_NEED_PROTOCOL_PROBE}" == "1" || "${CASE_NEED_H2_UPSTREAM}" == "1" || "${CASE_NEED_H2C_UPSTREAM}" == "1" || "${CASE_NEED_H1_STALL_UPSTREAM}" == "1" || "${CASE_NEED_H3_UPSTREAM}" == "1" || "${CASE_NEED_WEBTRANSPORT_UPSTREAM}" == "1" || "${CASE_NEED_WEBSOCKET_UPSTREAM}" == "1" || "${CASE_NEED_TURN_UDP_UPSTREAM}" == "1" || "${CASE_NEED_TURN_TCP_UPSTREAM}" == "1" || "${CASE_NEED_TURN_TLS_UPSTREAM}" == "1" ]]; then
  ensure_helper_image \
    "${protocol_probe_image}" \
    remove_protocol_probe_image \
    "${repo_root}/tests/docker/protocol_probe/Dockerfile" \
    "${repo_root}/tests/docker/protocol_probe"
fi

if [[ "${CASE_NEED_POSTGRES}" == "1" ]]; then
  ensure_helper_image \
    "${postgres_image}" \
    remove_postgres_image \
    "${repo_root}/tests/docker/postgres/Dockerfile" \
    "${repo_root}/tests/docker/postgres"
fi

if [[ "${CASE_NEED_REDIS}" == "1" ]]; then
  require_preloaded_helper_image "${redis_image}"
  docker run -d \
    --name "${redis_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-redis \
    "${redis_image}" >/dev/null

  for _attempt in $(seq 1 30); do
    if redis_is_ready; then
      break
    fi
    sleep 1
  done
  if ! redis_is_ready; then
    fail_with_diagnostics "Redis/Valkey did not become ready"
  fi
fi

if [[ -z "${OXIBELT_DOCKER_IMAGE:-}" ]]; then
  remove_proxy_image=1
  docker_build_with_retry \
    -t "${proxy_image}" \
    -f "${repo_root}/source/ops/Dockerfile.alpine" \
    "${repo_root}" >/dev/null
fi

remote_signer_token=""
remote_signer_docker_args=()
if [[ "${CASE_NEED_REMOTE_SIGNER}" == "1" ]]; then
  remote_signer_token="$(openssl rand -base64 32)"
  docker volume create --label "${test_label}" "${remote_signer_socket_volume}" >/dev/null
  docker run --rm \
    --label "${test_label}" \
    --user 0:0 \
    --mount "type=volume,src=${remote_signer_socket_volume},dst=/run/oxibelt-keysigner" \
    --entrypoint sh \
    "${proxy_image}" \
    -c 'chown 10001:10001 /run/oxibelt-keysigner && chmod 0770 /run/oxibelt-keysigner' >/dev/null

  docker create \
    --name "${remote_signer_container}" \
    --label "${test_label}" \
    --user 10001:10001 \
    --network "${network_name}" \
    --mount "type=volume,src=${remote_signer_socket_volume},dst=/run/oxibelt-keysigner" \
    --env "OXIBELT_KEYSIGNER_TOKEN=${remote_signer_token}" \
    --entrypoint /usr/local/bin/oxibelt-keysigner \
    "${proxy_image}" \
    --socket /run/oxibelt-keysigner/sign.sock \
    --key edge-default=/tmp/privkey.pem \
    --token-env OXIBELT_KEYSIGNER_TOKEN \
    --socket-mode 0660 \
    --max-connections 256 \
    --io-timeout-ms 5000 >/dev/null
  docker cp "${cert_dir}/privkey.pem" "${remote_signer_container}:/tmp/privkey.pem"
  docker start "${remote_signer_container}" >/dev/null
  for _attempt in $(seq 1 100); do
    if docker exec "${remote_signer_container}" sh -c 'test -S /run/oxibelt-keysigner/sign.sock' >/dev/null 2>&1; then
      break
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "${remote_signer_container}" 2>/dev/null || echo false)" != "true" ]]; then
      fail_with_diagnostics "remote signer exited before creating its socket"
    fi
    sleep 0.05
  done
  if ! docker exec "${remote_signer_container}" sh -c 'test -S /run/oxibelt-keysigner/sign.sock' >/dev/null 2>&1; then
    fail_with_diagnostics "remote signer socket was not created"
  fi
  remote_signer_docker_args+=(
    --mount "type=volume,src=${remote_signer_socket_volume},dst=/run/oxibelt-keysigner"
    -e "OXIBELT_KEYSIGNER_TOKEN=${remote_signer_token}"
  )
fi

if [[ "${CASE_NEED_HTTP_UPSTREAM}" == "1" ]]; then
  docker run -d \
    --name "${http_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-http \
    -e LISTEN_PORT=18080 \
    -e UPSTREAM_NAME=http-upstream \
    -e ACCEPT_PROXY_PROTOCOL=1 \
    "${mock_image}" >/dev/null
fi

if [[ "${CASE_NEED_ALT_UPSTREAM}" == "1" ]]; then
  docker run -d \
    --name "${alt_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-alt \
    -e LISTEN_PORT=18081 \
    -e UPSTREAM_NAME=alt-upstream \
    -e ACCEPT_PROXY_PROTOCOL=1 \
    "${mock_image}" >/dev/null
fi

if [[ "${CASE_NEED_KUBERNETES_SERVER}" == "1" ]]; then
  if [[ "${CASE_NEED_HTTP_UPSTREAM}" != "1" || "${CASE_NEED_ALT_UPSTREAM}" != "1" ]]; then
    fail_with_diagnostics "Kubernetes mock matrix cases require the HTTP and alternate upstreams"
  fi
  http_container_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${http_container}")"
  alt_container_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${alt_container}")"
  if [[ -z "${http_container_ip}" || -z "${alt_container_ip}" ]]; then
    fail_with_diagnostics "failed to inspect mock upstream IPs for Kubernetes case"
  fi
  docker run -d \
    --name "${kubernetes_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-kubernetes \
    -e LISTEN_PORT=18090 \
    -e EXPECTED_TOKEN=matrix-kubernetes-token \
    -e INITIAL_ENDPOINT_IP="${http_container_ip}" \
    -e UPDATED_ENDPOINT_IP="${alt_container_ip}" \
    -e MODIFIED_DELAY_SECONDS=5.0 \
    -e DELETED_DELAY_SECONDS=4.0 \
    "${mock_kubernetes_image}" >/dev/null
fi

if [[ "${CASE_NEED_HTTPS_UPSTREAM}" == "1" ]]; then
  docker create \
    --name "${https_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-https \
    -e LISTEN_PORT=18443 \
    -e UPSTREAM_NAME=https-upstream \
    -e TLS_CERT_FILE=/tls/server.pem \
    -e TLS_KEY_FILE=/tls/server.key \
    "${mock_image}" >/dev/null
  docker cp "${upstream_tls_dir}/server.pem" "${https_container}:/tls/server.pem"
  docker cp "${upstream_tls_dir}/server.key" "${https_container}:/tls/server.key"
  docker start "${https_container}" >/dev/null
fi

if [[ "${CASE_NEED_H2_UPSTREAM}" == "1" ]]; then
  docker create \
    --name "${h2_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-h2 \
    "${protocol_probe_image}" \
    h2-upstream \
    --listen 0.0.0.0:18444 \
    --cert /tls/server.pem \
    --key /tls/server.key \
    --name h2-upstream >/dev/null
  docker cp "${upstream_tls_dir}/server.pem" "${h2_container}:/tls/server.pem"
  docker cp "${upstream_tls_dir}/server.key" "${h2_container}:/tls/server.key"
  docker start "${h2_container}" >/dev/null
fi

if [[ "${CASE_NEED_H2C_UPSTREAM}" == "1" ]]; then
  docker run -d \
    --name "${h2c_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-h2c \
    "${protocol_probe_image}" \
    h2c-upstream \
    --listen 0.0.0.0:18082 \
    --name h2c-upstream >/dev/null
fi

if [[ "${CASE_NEED_H1_STALL_UPSTREAM}" == "1" ]]; then
  docker run -d \
    --name "${h1_stall_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-stall-h1 \
    "${protocol_probe_image}" \
    h1-stall-upstream \
    --listen 0.0.0.0:18083 \
    --name h1-stall-upstream \
    --read-delay-ms 1500 >/dev/null
fi

if [[ "${CASE_NEED_H3_UPSTREAM}" == "1" ]]; then
  docker create \
    --name "${h3_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-h3 \
    "${protocol_probe_image}" \
    h3-upstream \
    --listen 0.0.0.0:18445 \
    --cert /tls/server.pem \
    --key /tls/server.key \
    --name h3-upstream >/dev/null
  docker cp "${upstream_tls_dir}/server.pem" "${h3_container}:/tls/server.pem"
  docker cp "${upstream_tls_dir}/server.key" "${h3_container}:/tls/server.key"
  docker start "${h3_container}" >/dev/null
fi

if [[ "${CASE_NEED_WEBTRANSPORT_UPSTREAM}" == "1" ]]; then
  docker create \
    --name "${webtransport_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-webtransport \
    "${protocol_probe_image}" \
    webtransport-upstream \
    --listen 0.0.0.0:18446 \
    --cert /tls/server.pem \
    --key /tls/server.key \
    --name webtransport-upstream >/dev/null
  docker cp "${upstream_tls_dir}/server.pem" "${webtransport_container}:/tls/server.pem"
  docker cp "${upstream_tls_dir}/server.key" "${webtransport_container}:/tls/server.key"
  docker start "${webtransport_container}" >/dev/null
fi

if [[ "${CASE_NEED_WEBSOCKET_UPSTREAM}" == "1" ]]; then
  docker run -d \
    --name "${websocket_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-websocket \
    "${protocol_probe_image}" \
    websocket-echo-upstream \
    --listen 0.0.0.0:18081 >/dev/null
fi

if [[ "${CASE_NEED_TURN_UDP_UPSTREAM}" == "1" ]]; then
  docker run -d \
    --name "${turn_udp_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-turn-udp \
    "${protocol_probe_image}" \
    turn-upstream \
    --transport udp \
    --listen 0.0.0.0:3478 >/dev/null
fi

if [[ "${CASE_NEED_TURN_TCP_UPSTREAM}" == "1" ]]; then
  docker run -d \
    --name "${turn_tcp_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-turn-tcp \
    "${protocol_probe_image}" \
    turn-upstream \
    --transport tcp \
    --listen 0.0.0.0:3479 >/dev/null
fi

if [[ "${CASE_NEED_TURN_TLS_UPSTREAM}" == "1" ]]; then
  docker create \
    --name "${turn_tls_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-turn-tls \
    "${protocol_probe_image}" \
    turn-upstream \
    --transport tls \
    --listen 0.0.0.0:5349 \
    --cert /tls/server.pem \
    --key /tls/server.key >/dev/null
  docker cp "${upstream_tls_dir}/server.pem" "${turn_tls_container}:/tls/server.pem"
  docker cp "${upstream_tls_dir}/server.key" "${turn_tls_container}:/tls/server.key"
  docker start "${turn_tls_container}" >/dev/null
fi

proxy_dns_args=()
if [[ "${CASE_NEED_DNS_SERVER}" == "1" ]]; then
  if [[ "${CASE_NEED_HTTP_UPSTREAM}" != "1" ]]; then
    fail_with_diagnostics "DNS server matrix cases require the HTTP upstream"
  fi
  http_container_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${http_container}")"
  if [[ -z "${http_container_ip}" ]]; then
    fail_with_diagnostics "failed to inspect mock HTTP upstream IP for DNS case"
  fi
  docker run -d \
    --name "${dns_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-dns \
    -e VALID_A_NAME=valid.discovery.test \
    -e VALID_A_IP="${http_container_ip}" \
    -e SPOOF_A_NAME=spoofed.discovery.test \
    -e SPOOF_A_IP=203.0.113.66 \
    -e LISTEN_HOST=0.0.0.0 \
    "${mock_dns_image}" >/dev/null
  dns_container_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${dns_container}")"
  if [[ -z "${dns_container_ip}" ]]; then
    fail_with_diagnostics "failed to inspect mock DNS server IP"
  fi
  proxy_dns_args+=(--dns "${dns_container_ip}" --add-host "mock-http:${http_container_ip}")
  sleep 1
fi

if [[ "${CASE_NEED_POSTGRES}" == "1" ]]; then
  cat >"${work_dir}/postgres-init.sql" <<'EOF'
CREATE TABLE oxibelt_access_log (
  event text NOT NULL,
  timestamp_unix_ms bigint NOT NULL,
  record jsonb NOT NULL
);
EOF
  if [[ -f "${case_dir}/postgres-init.sql" ]]; then
    cat "${case_dir}/postgres-init.sql" >>"${work_dir}/postgres-init.sql"
  fi

  if [[ "${CASE_NEED_POSTGRES_MTLS}" == "1" ]]; then
    cat >"${work_dir}/pg_hba.conf" <<'EOF'
local all all trust
hostssl oxibelt oxibelt all scram-sha-256 clientcert=verify-full
hostnossl all all all reject
EOF
    docker create \
      --name "${postgres_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --network-alias mock-postgres \
      -e POSTGRES_USER=oxibelt \
      -e POSTGRES_PASSWORD=oxibelt \
      -e POSTGRES_DB=oxibelt \
      --entrypoint /bin/sh \
      "${postgres_image}" \
      -ceu 'chown -R postgres:postgres /tls && chmod 0600 /tls/*.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tls/server.pem -c ssl_key_file=/tls/server.key -c ssl_ca_file=/tls/ca.pem -c hba_file=/tls/pg_hba.conf' >/dev/null
    docker cp "${postgres_tls_dir}/server.pem" "${postgres_container}:/tls/server.pem"
    docker cp "${postgres_tls_dir}/server.key" "${postgres_container}:/tls/server.key"
    docker cp "${postgres_tls_dir}/ca.pem" "${postgres_container}:/tls/ca.pem"
    docker cp "${work_dir}/pg_hba.conf" "${postgres_container}:/tls/pg_hba.conf"
  else
    docker create \
      --name "${postgres_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --network-alias mock-postgres \
      -e POSTGRES_USER=oxibelt \
      -e POSTGRES_PASSWORD=oxibelt \
      -e POSTGRES_DB=oxibelt \
      "${postgres_image}" >/dev/null
  fi
  docker cp "${work_dir}/postgres-init.sql" "${postgres_container}:/docker-entrypoint-initdb.d/10-oxibelt.sql"
  docker start "${postgres_container}" >/dev/null

  for _attempt in $(seq 1 30); do
    if postgres_is_ready; then
      break
    fi
    sleep 1
  done
  if ! postgres_is_ready; then
    fail_with_diagnostics "PostgreSQL did not become ready"
  fi
fi

docker create \
  --name "${proxy_container}" \
  --label "${test_label}" \
  --network "${network_name}" \
  --network-alias proxy \
  -e OXIBELT_ADMIN_TOKEN=matrix-admin-token \
  -e OXIBELT_VIEWER_TOKEN=matrix-viewer-token \
  -e OXIBELT_UPSTREAM_TOKEN=matrix-upstream-token \
  -e OXIBELT_SECURITY_TOKEN=matrix-security-token \
  -e OXIBELT_DYNAMIC_POLICY_HMAC_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= \
  -e OXIBELT_CACHE_PURGE_HMAC_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= \
  -e OXIBELT_INSTANCE_ID=proxy-a \
  -e KUBERNETES_SERVICE_TOKEN=matrix-kubernetes-token \
  "${remote_signer_docker_args[@]}" \
  "${proxy_dns_args[@]}" \
  "${proxy_image}" >/dev/null
docker cp "${case_dir}/config/." "${proxy_container}:/etc/oxibelt/config"
docker cp "${proxy_cert_dir}/." "${proxy_container}:/etc/oxibelt/cert"
if [[ -d "${case_dir}/oxirule" ]]; then
  docker cp "${case_dir}/oxirule/." "${proxy_container}:/etc/oxibelt/oxirule"
fi

if [[ "${CASE_NEED_SECOND_PROXY}" == "1" ]]; then
  docker create \
    --name "${proxy_b_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias proxy-b \
    -e OXIBELT_ADMIN_TOKEN=matrix-admin-token \
    -e OXIBELT_VIEWER_TOKEN=matrix-viewer-token \
    -e OXIBELT_UPSTREAM_TOKEN=matrix-upstream-token \
    -e OXIBELT_SECURITY_TOKEN=matrix-security-token \
    -e OXIBELT_DYNAMIC_POLICY_HMAC_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= \
    -e OXIBELT_CACHE_PURGE_HMAC_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= \
    -e OXIBELT_INSTANCE_ID=proxy-b \
    -e KUBERNETES_SERVICE_TOKEN=matrix-kubernetes-token \
    "${remote_signer_docker_args[@]}" \
    "${proxy_dns_args[@]}" \
    "${proxy_image}" >/dev/null
  docker cp "${case_dir}/config/." "${proxy_b_container}:/etc/oxibelt/config"
  docker cp "${proxy_cert_dir}/." "${proxy_b_container}:/etc/oxibelt/cert"
  if [[ -d "${case_dir}/oxirule" ]]; then
    docker cp "${case_dir}/oxirule/." "${proxy_b_container}:/etc/oxibelt/oxirule"
  fi
fi

if [[ "${CASE_EXPECT_START}" == "failure" ]]; then
  docker start "${proxy_container}" >/dev/null || true
  for _attempt in $(seq 1 30); do
    if [[ "$(docker inspect -f '{{.State.Running}}' "${proxy_container}" 2>/dev/null || echo false)" == "false" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "$(docker inspect -f '{{.State.Running}}' "${proxy_container}" 2>/dev/null || echo false)" == "true" ]]; then
    fail_with_diagnostics "proxy unexpectedly stayed running for invalid case ${category}/${case_name}"
  fi
  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  if [[ -n "${CASE_EXPECT_FAILURE_CONTAINS}" ]] && ! grep -F "${CASE_EXPECT_FAILURE_CONTAINS}" <<<"${logs}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "proxy failure did not contain expected text: ${CASE_EXPECT_FAILURE_CONTAINS}"
  fi
  echo "Docker matrix invalid case ${category}/${case_name} failed as expected"
  exit 0
fi

docker start "${proxy_container}" >/dev/null
if [[ "${CASE_NEED_SECOND_PROXY}" == "1" ]]; then
  docker start "${proxy_b_container}" >/dev/null
fi
sleep 1
if [[ "$(docker inspect -f '{{.State.Running}}' "${proxy_container}" 2>/dev/null || echo false)" != "true" ]]; then
  fail_with_diagnostics "proxy exited during startup for ${category}/${case_name}"
fi
if [[ "${CASE_NEED_SECOND_PROXY}" == "1" && "$(docker inspect -f '{{.State.Running}}' "${proxy_b_container}" 2>/dev/null || echo false)" != "true" ]]; then
  fail_with_diagnostics "second proxy exited during startup for ${category}/${case_name}"
fi

if [[ -s "${case_dir}/checks.sh" ]]; then
  # shellcheck source=/dev/null
  source "${case_dir}/checks.sh"
  if declare -F run_case_checks >/dev/null; then
    run_case_checks
  fi
fi

if [[ "${CASE_NEED_PQ_PROBE}" == "1" ]]; then
  pq_x25519_output="$(run_pq_probe "x25519")"
  if ! grep -F 'requested_group=X25519 negotiated_group=X25519' <<<"${pq_x25519_output}" >/dev/null; then
    echo "${pq_x25519_output}" >&2
    fail_with_diagnostics "X25519 probe did not negotiate the expected group"
  fi

  pq_hybrid_output="$(run_pq_probe "x25519mlkem768")"
  if ! grep -F 'requested_group=X25519MLKEM768 negotiated_group=X25519MLKEM768' <<<"${pq_hybrid_output}" >/dev/null; then
    echo "${pq_hybrid_output}" >&2
    fail_with_diagnostics "X25519MLKEM768 probe did not negotiate the expected group"
  fi
fi

echo "Docker matrix case ${category}/${case_name} passed"
