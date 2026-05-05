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
upstream_tls_dir="${work_dir}/upstream-tls"
logs_dir="${work_dir}/logs"
network_name="oxibelt-matrix-${run_id}"
mock_image="oxibelt/mock-upstream:${run_id}"
pq_probe_image="oxibelt/pq-probe:${run_id}"
protocol_probe_image="oxibelt/protocol-probe:${run_id}"
proxy_image="${OXIBELT_DOCKER_IMAGE:-oxibelt/proxy-matrix:${run_id}}"
remove_proxy_image=0
proxy_container="oxibelt-proxy-${run_id}"
http_container="oxibelt-http-${run_id}"
https_container="oxibelt-https-${run_id}"
alt_container="oxibelt-alt-${run_id}"
h2_container="oxibelt-h2-${run_id}"
h2c_container="oxibelt-h2c-${run_id}"
test_label="oxibelt.test.run=${run_id}"

cleanup() {
  docker ps -aq --filter "label=${test_label}" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "${network_name}" >/dev/null 2>&1 || true
  docker rmi -f "${mock_image}" "${pq_probe_image}" "${protocol_probe_image}" >/dev/null 2>&1 || true
  if [[ "${remove_proxy_image}" == "1" ]]; then
    docker rmi -f "${proxy_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${KEEP_TEST_ARTIFACTS:-0}" != "1" ]]; then
    rm -rf "${work_dir}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "${case_dir}" "${cert_dir}" "${upstream_tls_dir}" "${logs_dir}"

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
  docker logs "${http_container}" >"${logs_dir}/mock-http.log" 2>&1 || true
  docker logs "${https_container}" >"${logs_dir}/mock-https.log" 2>&1 || true
  docker logs "${alt_container}" >"${logs_dir}/mock-alt.log" 2>&1 || true
  docker logs "${h2_container}" >"${logs_dir}/mock-h2.log" 2>&1 || true
  docker logs "${h2c_container}" >"${logs_dir}/mock-h2c.log" 2>&1 || true

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

client_request() {
  client_request_with_headers "$1" "$2" "$3" "GET" ""
}

client_request_with_headers() {
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

  for _attempt in $(seq 1 30); do
    client_container="oxibelt-client-${run_id}-${RANDOM}"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --entrypoint python \
      "${mock_image}" \
      /opt/mock_upstream/client.py \
      --path "${path}" \
      --host "${host}" \
      --method "${method}" \
      --body "${body}" \
      --ca-file /tmp/proxy-ca.pem \
      --dump-response-json \
      --expect-status "${expect_status}" \
      "${header_args[@]}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker start -a "${client_container}" 2>&1)"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "client request failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "client request did not reach expected status ${expect_status}"
}

protocol_probe_client() {
  local protocol="$1"
  local authority="$2"
  local path="$3"
  local expect_status="$4"
  local output=""
  local status=0
  local client_container=""

  for _attempt in $(seq 1 30); do
    client_container="oxibelt-protocol-client-${run_id}-${RANDOM}"
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
      --ca-cert /tmp/proxy-ca.pem \
      --expect-status "${expect_status}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker start -a "${client_container}" 2>&1)"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "protocol probe client failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "protocol probe did not reach expected status ${expect_status}"
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
IP.1 = 127.0.0.1
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

cp "${upstream_tls_dir}/ca.pem" "${cert_dir}/upstream-ca.pem"
printf 'ocsp' >"${cert_dir}/ocsp.der"
printf 'not an ECHConfigList' >"${cert_dir}/invalid.echconfiglist"
chmod 644 "${cert_dir}/"* "${upstream_tls_dir}/"*

docker network create "${network_name}" >/dev/null

if [[ "${CASE_EXPECT_START}" == "success" || "${CASE_NEED_HTTP_UPSTREAM}" == "1" || "${CASE_NEED_HTTPS_UPSTREAM}" == "1" || "${CASE_NEED_ALT_UPSTREAM}" == "1" ]]; then
  docker build \
    -t "${mock_image}" \
    -f "${repo_root}/tests/docker/mock_upstream/Dockerfile" \
    "${repo_root}/tests/docker/mock_upstream" >/dev/null
fi

if [[ "${CASE_NEED_PQ_PROBE}" == "1" ]]; then
  docker build \
    -t "${pq_probe_image}" \
    -f "${repo_root}/tests/docker/pq_probe/Dockerfile" \
    "${repo_root}/tests/docker/pq_probe" >/dev/null
fi

if [[ "${CASE_NEED_PROTOCOL_PROBE}" == "1" || "${CASE_NEED_H2_UPSTREAM}" == "1" || "${CASE_NEED_H2C_UPSTREAM}" == "1" ]]; then
  docker build \
    -t "${protocol_probe_image}" \
    -f "${repo_root}/tests/docker/protocol_probe/Dockerfile" \
    "${repo_root}/tests/docker/protocol_probe" >/dev/null
fi

if [[ -z "${OXIBELT_DOCKER_IMAGE:-}" ]]; then
  remove_proxy_image=1
  docker build \
    -t "${proxy_image}" \
    -f "${repo_root}/source/ops/Dockerfile.alpine" \
    "${repo_root}" >/dev/null
fi

if [[ "${CASE_NEED_HTTP_UPSTREAM}" == "1" ]]; then
  docker run -d \
    --name "${http_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-http \
    -e LISTEN_PORT=18080 \
    -e UPSTREAM_NAME=http-upstream \
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
    "${mock_image}" >/dev/null
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

docker create \
  --name "${proxy_container}" \
  --label "${test_label}" \
  --network "${network_name}" \
  --network-alias proxy \
  "${proxy_image}" >/dev/null
docker cp "${case_dir}/config/." "${proxy_container}:/etc/oxibelt/config"
docker cp "${cert_dir}/." "${proxy_container}:/etc/oxibelt/cert"
if [[ -d "${case_dir}/oxirule" ]]; then
  docker cp "${case_dir}/oxirule/." "${proxy_container}:/etc/oxibelt/oxirule"
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
sleep 1
if [[ "$(docker inspect -f '{{.State.Running}}' "${proxy_container}" 2>/dev/null || echo false)" != "true" ]]; then
  fail_with_diagnostics "proxy exited during startup for ${category}/${case_name}"
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
