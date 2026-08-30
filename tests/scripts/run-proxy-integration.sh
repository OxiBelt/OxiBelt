#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
run_id="$(date +%s)-$$"
work_dir="${repo_root}/tests/.tmp/${run_id}"
network_name="oxibelt-it-${run_id}"
mock_image="oxibelt/mock-upstream:${run_id}"
proxy_image="oxibelt/proxy-it:${run_id}"
pq_probe_image="oxibelt/pq-probe:${run_id}"
http_container="oxibelt-http-${run_id}"
alternate_upgrade_container="oxibelt-alternate-upgrade-${run_id}"
https_container="oxibelt-https-${run_id}"
proxy_container="oxibelt-proxy-${run_id}"
test_label="oxibelt.test.run=${run_id}"

cleanup() {
  docker ps -aq --filter "label=${test_label}" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker rm -f \
    "${proxy_container}" \
    "${https_container}" \
    "${alternate_upgrade_container}" \
    "${http_container}" >/dev/null 2>&1 || true
  docker network rm "${network_name}" >/dev/null 2>&1 || true
  docker rmi -f "${proxy_image}" "${mock_image}" "${pq_probe_image}" >/dev/null 2>&1 || true
  if [[ "${KEEP_TEST_ARTIFACTS:-0}" != "1" ]]; then
    rm -rf "${work_dir}"
  fi
}
trap cleanup EXIT

mkdir -p \
  "${work_dir}/proxy-tls" \
  "${work_dir}/static/attacker-controlled" \
  "${work_dir}/static/public" \
  "${work_dir}/upstream-tls"
printf '%s' "INSIDE_VALIDATED_ROOT" >"${work_dir}/static/public/secret.txt"
printf '%s' "OUTSIDE_VALIDATED_ROOT" >"${work_dir}/static/attacker-controlled/secret.txt"

cat > "${work_dir}/upstream-ca.cnf" <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = oxibelt-test-root

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat > "${work_dir}/upstream-leaf.cnf" <<'EOF'
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
EOF

cat > "${work_dir}/downstream.cnf" <<'EOF'
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
  -keyout "${work_dir}/upstream-tls/ca.key" \
  -out "${work_dir}/upstream-tls/ca.pem" >/dev/null 2>&1

openssl req -newkey rsa:2048 -sha256 -nodes \
  -config "${work_dir}/upstream-leaf.cnf" \
  -keyout "${work_dir}/upstream-tls/server.key" \
  -out "${work_dir}/upstream-tls/server.csr" >/dev/null 2>&1

openssl x509 -req -sha256 -days 1 \
  -in "${work_dir}/upstream-tls/server.csr" \
  -CA "${work_dir}/upstream-tls/ca.pem" \
  -CAkey "${work_dir}/upstream-tls/ca.key" \
  -CAcreateserial \
  -extfile "${work_dir}/upstream-leaf.cnf" \
  -extensions req_ext \
  -out "${work_dir}/upstream-tls/server.pem" >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 1 \
  -config "${work_dir}/downstream.cnf" \
  -keyout "${work_dir}/proxy-tls/privkey.pem" \
  -out "${work_dir}/proxy-tls/fullchain.pem" >/dev/null 2>&1

cat > "${work_dir}/oxibelt.toml" <<'EOF'
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true

[listeners]
https_bind = "0.0.0.0:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = ["upstream-ca.pem"]

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[proxy.upgrades]
websocket = true
generic_http_upgrade = true
connect_tunneling = false

[compression]
enabled = true
gzip = true
deflate = true
zstd = true

[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "block-integration-waf-path"
phase = "request"
priority = 100
when = "Request.Http.Path.endsWith('/blocked')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Blocked by WAF"

[[upstreams]]
name = "http-upstream"
origin = "http://mock-http:18080/origin"
max_http_version = "h1"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true

[upstreams.tls.ech]
mode = "disabled"

[[upstreams]]
name = "alternate-upgrade"
origin = "http://mock-alternate-upgrade:18082"
max_http_version = "h1"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = false
webtransport = false

[upstreams.tls.ech]
mode = "disabled"

[[upstreams]]
name = "https-upstream"
origin = "https://mock-https:18443/backend"
max_http_version = "h1"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = true
websocket = true
webrtc = true
webtransport = true

[upstreams.tls.ech]
mode = "grease"

[[routes]]
name = "http-route"
hosts = ["http.example.test"]
path_prefix = "/app"
upstream = "http-upstream"

[[routes]]
name = "mixed-upgrade-blocked-route"
hosts = ["mixed-upgrade-blocked.example.test"]
path_prefix = "/upgrade"
upstream = "alternate-upgrade"

[[routes]]
name = "generic-upgrade-route"
hosts = ["generic-upgrade.example.test"]
path_prefix = "/upgrade"
upstream = "alternate-upgrade"
generic_http_upgrade = true

[[routes]]
name = "websocket-mismatch-route"
hosts = ["websocket-mismatch.example.test"]
path_prefix = "/upgrade"
upstream = "alternate-upgrade"

[[routes]]
name = "https-route"
hosts = ["secure.example.test"]
path_prefix = "/secure"
replace_prefix_with = "/edge"
upstream = "https-upstream"

[[routes]]
name = "static-route"
hosts = ["static.example.test"]
path_prefix = "/assets"
static_root = "/etc/oxibelt/static/public"
EOF

cp "${work_dir}/upstream-tls/ca.pem" "${work_dir}/proxy-tls/upstream-ca.pem"
chmod 644 \
  "${work_dir}/proxy-tls/fullchain.pem" \
  "${work_dir}/proxy-tls/privkey.pem" \
  "${work_dir}/proxy-tls/upstream-ca.pem" \
  "${work_dir}/upstream-tls/ca.pem" \
  "${work_dir}/upstream-tls/server.pem" \
  "${work_dir}/upstream-tls/server.key"

echo "Building mock upstream image"
docker build \
  -t "${mock_image}" \
  -f "${repo_root}/tests/docker/mock_upstream/Dockerfile" \
  "${repo_root}/tests/docker/mock_upstream"

echo "Building proxy runtime image"
docker build \
  -t "${proxy_image}" \
  -f "${repo_root}/source/ops/Dockerfile.alpine" \
  "${repo_root}"

echo "Building post-quantum probe image"
docker build \
  -t "${pq_probe_image}" \
  -f "${repo_root}/tests/docker/pq_probe/Dockerfile" \
  "${repo_root}/tests/docker/pq_probe"

docker network create "${network_name}" >/dev/null

docker run -d \
  --name "${http_container}" \
  --network "${network_name}" \
  --network-alias mock-http \
  -e LISTEN_PORT=18080 \
  -e UPSTREAM_NAME=http-upstream \
  "${mock_image}" >/dev/null

docker run -d \
  --name "${alternate_upgrade_container}" \
  --network "${network_name}" \
  --network-alias mock-alternate-upgrade \
  -e LISTEN_PORT=18082 \
  -e UPSTREAM_NAME=alternate-upgrade \
  -e UPGRADE_RESPONSE_TOKEN=h2c \
  "${mock_image}" >/dev/null

docker create \
  --name "${https_container}" \
  --network "${network_name}" \
  --network-alias mock-https \
  -e LISTEN_PORT=18443 \
  -e UPSTREAM_NAME=https-upstream \
  -e TLS_CERT_FILE=/tls/server.pem \
  -e TLS_KEY_FILE=/tls/server.key \
  "${mock_image}" >/dev/null
docker cp "${work_dir}/upstream-tls/server.pem" "${https_container}:/tls/server.pem"
docker cp "${work_dir}/upstream-tls/server.key" "${https_container}:/tls/server.key"
docker start "${https_container}" >/dev/null

docker create \
  --name "${proxy_container}" \
  --network "${network_name}" \
  --network-alias proxy \
  "${proxy_image}" >/dev/null
docker cp "${work_dir}/oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
docker cp "${work_dir}/proxy-tls/." "${proxy_container}:/etc/oxibelt/cert"
docker cp "${work_dir}/static" "${proxy_container}:/etc/oxibelt/static"
docker start "${proxy_container}" >/dev/null

request_through_proxy() {
  local target="$1"
  local host="$2"
  local client_container="oxibelt-client-${run_id}-${RANDOM}"
  local status=0

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --target "${target}" \
    --host "${host}" \
    --ca-file /tmp/proxy-ca.pem >/dev/null
  docker cp "${work_dir}/proxy-tls/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  if docker start -a "${client_container}"; then
    status=0
  else
    status=$?
  fi

  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  return "${status}"
}

request_path_through_proxy() {
  local path="$1"
  local host="$2"
  local expect_status="$3"
  local client_container="oxibelt-client-${run_id}-${RANDOM}"
  local status=0

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --path "${path}" \
    --host "${host}" \
    --ca-file /tmp/proxy-ca.pem \
    --dump-response-json \
    --expect-status "${expect_status}" >/dev/null
  docker cp "${work_dir}/proxy-tls/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  if docker start -a "${client_container}"; then
    status=0
  else
    status=$?
  fi

  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  return "${status}"
}

upgrade_through_proxy() {
  local path="$1"
  local host="$2"
  local upgrade_offer="$3"
  local expect_status="$4"
  local body="$5"
  local headers_only="$6"
  local client_container="oxibelt-client-${run_id}-${RANDOM}"
  local status=0
  local client_args=(
    /opt/mock_upstream/client.py
    --path "${path}"
    --host "${host}"
    --ca-file /tmp/proxy-ca.pem
    --upgrade-token "${upgrade_offer}"
    --body "${body}"
    --dump-response-json
    --expect-status "${expect_status}"
  )

  if [[ "${headers_only}" == "1" ]]; then
    client_args+=(--upgrade-headers-only)
  fi

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    "${client_args[@]}" >/dev/null
  docker cp "${work_dir}/proxy-tls/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  if docker start -a "${client_container}"; then
    status=0
  else
    status=$?
  fi

  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  return "${status}"
}

run_pq_probe() {
  local group="$1"
  local expect="$2"
  local container_name="oxibelt-pq-${group}-${run_id}"
  local output=""
  local status=0

  docker create \
    --name "${container_name}" \
    --network "${network_name}" \
    "${pq_probe_image}" \
    --host proxy \
    --port 8443 \
    --server-name proxy \
    --ca-cert /tmp/downstream-ca.pem \
    --group "${group}" >/dev/null
  docker cp "${work_dir}/proxy-tls/fullchain.pem" "${container_name}:/tmp/downstream-ca.pem"

  if output="$(docker start -a "${container_name}" 2>&1)"; then
    status=0
  else
    status=$?
  fi

  docker rm -f "${container_name}" >/dev/null 2>&1 || true
  echo "${output}"

  if [[ "${expect}" == "success" ]]; then
    if [[ "${status}" -ne 0 ]]; then
      echo "post-quantum probe with group ${group} unexpectedly failed" >&2
      exit 1
    fi
  else
    if [[ "${status}" -eq 0 ]]; then
      echo "post-quantum probe with group ${group} unexpectedly succeeded" >&2
      exit 1
    fi
  fi
}

for _attempt in $(seq 1 20); do
  if http_response="$(request_through_proxy "http-ping" "http.example.test" 2>/dev/null)"; then
    break
  fi
  http_response=""
  sleep 1
done

if [[ -z "${http_response:-}" ]]; then
  echo "proxy did not become ready in time" >&2
  docker logs "${proxy_container}" >&2 || true
  exit 1
fi

https_response="$(request_through_proxy "secure-health" "secure.example.test")"

echo "${http_response}" | grep -F '"upstream": "http-upstream"'
echo "${http_response}" | grep -F '"path": "/origin/app/ping?source=http"'
echo "${http_response}" | grep -F '"x-forwarded-proto": "https"'
echo "${http_response}" | grep -F '"x-forwarded-host": "http.example.test"'

echo "${https_response}" | grep -F '"upstream": "https-upstream"'
echo "${https_response}" | grep -F '"path": "/backend/edge/v1/health?source=https"'
echo "${https_response}" | grep -F '"host": "secure.example.test"'
echo "${https_response}" | grep -F '"x-forwarded-host": "secure.example.test"'

valid_websocket_response="$(
  upgrade_through_proxy "/app/upgrade" "http.example.test" "websocket" 101 "" 1
)"
echo "${valid_websocket_response}" | grep -F '"status": 101'
echo "${valid_websocket_response}" | grep -F '"upgrade": "websocket"'

mixed_upgrade_blocked_response="$(
  upgrade_through_proxy \
    "/upgrade" \
    "mixed-upgrade-blocked.example.test" \
    "h2c, websocket" \
    501 \
    "" \
    0
)"
echo "${mixed_upgrade_blocked_response}" | grep -F '"status": 501'
echo "${mixed_upgrade_blocked_response}" | grep -F '"body": "unsupported HTTP upgrade request"'

websocket_mismatch_response="$(
  upgrade_through_proxy \
    "/upgrade" \
    "websocket-mismatch.example.test" \
    "websocket" \
    502 \
    "" \
    0
)"
echo "${websocket_mismatch_response}" | grep -F '"status": 502'
echo "${websocket_mismatch_response}" \
  | grep -F '"body": "upstream did not select the WebSocket upgrade protocol"'

generic_upgrade_response="$(
  upgrade_through_proxy \
    "/upgrade" \
    "generic-upgrade.example.test" \
    "h2c, websocket" \
    101 \
    "alternate-protocol" \
    0
)"
echo "${generic_upgrade_response}" | grep -F '"status": 101'
echo "${generic_upgrade_response}" | grep -F '"upgrade": "h2c"'
echo "${generic_upgrade_response}" | grep -F '"body": "upgraded:alternate-protocol"'

static_response="$(request_path_through_proxy "/assets/secret.txt" "static.example.test" 200)"
echo "${static_response}" | grep -F '"body": "INSIDE_VALIDATED_ROOT"'

docker exec -u 0 "${proxy_container}" sh -c \
  'rm -rf /etc/oxibelt/static/public && ln -s /etc/oxibelt/static/attacker-controlled /etc/oxibelt/static/public'
static_swap_response="$(request_path_through_proxy "/assets/secret.txt" "static.example.test" 403)"
echo "${static_swap_response}" | grep -F '"status": 403'
echo "${static_swap_response}" | grep -F '"body": "forbidden"'
if echo "${static_swap_response}" | grep -F 'OUTSIDE_VALIDATED_ROOT' >/dev/null; then
  echo "static_root swap exposed a file outside the validated static root" >&2
  exit 1
fi

waf_blocked_response=""
if waf_blocked_response="$(request_through_proxy "waf-blocked" "http.example.test" 2>/dev/null)"; then
  echo "WAF block request unexpectedly succeeded" >&2
  exit 1
fi
echo "${waf_blocked_response}" | grep -F 'Blocked by WAF'

pq_x25519_output="$(run_pq_probe "x25519" "success")"
echo "${pq_x25519_output}" | grep -F 'requested_group=X25519 negotiated_group=X25519'

pq_hybrid_output="$(run_pq_probe "x25519mlkem768" "success")"
echo "${pq_hybrid_output}" | grep -F 'requested_group=X25519MLKEM768 negotiated_group=X25519MLKEM768'

echo "HTTP and HTTPS proxy integration checks passed"
echo "WebSocket and generic HTTP Upgrade protocol binding checks passed"
echo "X25519 and X25519MLKEM768 both negotiate successfully with the current aws-lc-rs-based server"
echo "HTTPS upstream proxying succeeds with TLS 1.3 ECH GREASE enabled"
