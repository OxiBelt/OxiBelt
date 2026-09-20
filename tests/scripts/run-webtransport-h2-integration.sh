#!/usr/bin/env bash
# Independent raw-H2 oracle and existing H3 probe, over real TLS Docker listeners.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
run_id="wt-h2-$(date +%s)-$$"
work_dir="$(mktemp -d)"
network="oxibelt-${run_id}"
label="oxibelt.test.run=${run_id}"
proxy_image="${OXIBELT_DOCKER_IMAGE:-oxibelt/proxy:${run_id}}"
probe_image="${OXIBELT_PROTOCOL_PROBE_IMAGE:-oxibelt/protocol-probe:${run_id}}"

cleanup() {
  local status=$?
  if ((status != 0)); then
    for name in proxy upstream-h2 upstream-h2-closed upstream-h2-quic upstream-h3 drain-target; do
      if docker container inspect "${run_id}-${name}" >/dev/null 2>&1; then
        docker logs "${run_id}-${name}" 2>&1 | tail -100 || true
      fi
    done
  fi
  docker ps -aq --filter "label=${label}" | xargs -r docker rm -fv >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  if [[ -z "${OXIBELT_DOCKER_IMAGE:-}" ]]; then docker image rm "${proxy_image}" >/dev/null 2>&1 || true; fi
  if [[ -z "${OXIBELT_PROTOCOL_PROBE_IMAGE:-}" ]]; then docker image rm "${probe_image}" >/dev/null 2>&1 || true; fi
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 1 \
  -subj '/CN=OxiBelt WebTransport test CA' -addext 'basicConstraints=critical,CA:TRUE' \
  -keyout "${work_dir}/ca.key" -out "${work_dir}/ca.pem" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
  -subj '/CN=proxy' -keyout "${work_dir}/server.key" -out "${work_dir}/server.csr" >/dev/null 2>&1
cat >"${work_dir}/extensions.cnf" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:proxy,DNS:upstream-h2,DNS:upstream-h2-closed,DNS:upstream-h2-quic,DNS:upstream-h3
EOF
openssl x509 -req -in "${work_dir}/server.csr" -CA "${work_dir}/ca.pem" \
  -CAkey "${work_dir}/ca.key" -CAcreateserial -days 1 -sha256 \
  -extfile "${work_dir}/extensions.cnf" -out "${work_dir}/server.pem" >/dev/null 2>&1

cat >"${work_dir}/oxibelt.toml" <<'EOF'
[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
[runtime.accept]
workers = 1
reuse_port = false
backlog = 1024
accept_error_backoff_ms = 10
[listeners]
https_bind = "0.0.0.0:8443"
http1 = true
http2 = true
http3 = true
[quic.socket]
workers = 1
reuse_port = false
[tls]
cert_chain = "server.pem"
private_key = "server.key"
[tls.ocsp]
mode = "disabled"
[proxy]
trusted_ca_certs = ["ca.pem"]
[proxy.auto_upgrade]
enabled = true
max_http_version = "h3"
[proxy.http2.webtransport]
max_concurrent_uni_streams = 4
max_concurrent_bidi_streams = 4
max_stream_buffer_bytes = 1024
max_session_buffer_bytes = 4096
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"
[[waf.rules]]
name = "reject-webtransport-blocked-path"
phase = "request"
priority = 10
when = "Request.Protocol == 'webtransport' && Request.Http.Path.endsWith('/blocked')"
[[waf.rules.actions]]
type = "reject"
status = 403
body = "Blocked WebTransport request"
[[waf.rules]]
name = "silence-webtransport-request"
phase = "request"
priority = 11
when = "Request.Protocol == 'webtransport' && Request.Http.Path.endsWith('/silent-close')"
[[waf.rules.actions]]
type = "silent_close"
[[waf.rules]]
name = "close-webtransport-blocked-payload"
phase = "stream"
priority = 20
when = "Stream.Protocol == 'webtransport' && Stream.Direction == 'downstream_to_upstream' && Stream.Payload.contains('waf-block-stream')"
[[waf.rules.actions]]
type = "close_stream"
webtransport_code = 91
reason = "blocked WebTransport payload"
[[waf.rules]]
name = "reject-misclassified-upstream-webtransport-payload"
phase = "stream"
priority = 21
when = "Stream.Protocol == 'webtransport' && Stream.Direction == 'downstream_to_upstream' && Stream.Payload.contains('stop-probe')"
[[waf.rules.actions]]
type = "close_stream"
webtransport_code = 92
reason = "upstream WebTransport payload had downstream direction"
[admin]
enabled = true
bind = "0.0.0.0:9092"
bearer_token_env = "OXIBELT_ADMIN_TOKEN"
[admin.tls]
enabled = true
min_version = "tls1.2"
[[admin.tls.certificates]]
server_names = ["proxy"]
cert_chain = "server.pem"
private_key = "server.key"
default = true
[admin.operations]
webtransport = true
[admin.operations.event_compression]
enabled = true
br = true
zstd = true
gzip = true
deflate = true
level = 1
max_concurrent_streams = 4
[limits]
max_webtransport_sessions = 16
max_webtransport_sessions_per_connection = 4
[[upstreams]]
name = "h2"
origin = "https://upstream-h2:18443"
max_http_version = "h2"
webtransport = true
[upstreams.tls.ech]
mode = "disabled"
[[upstreams]]
name = "h2-closed"
origin = "https://upstream-h2-closed:18443"
max_http_version = "h2"
webtransport = true
[upstreams.tls.ech]
mode = "disabled"
[[upstreams]]
name = "h3"
origin = "https://upstream-h3:18443"
max_http_version = "h3"
webtransport = true
[upstreams.tls.ech]
mode = "disabled"
[[upstreams]]
name = "h2quic"
origin = "https://upstream-h2-quic:18443"
max_http_version = "h2"
webtransport = true
[upstreams.tls.ech]
mode = "disabled"
[[routes]]
name = "h2quic"
hosts = ["example.test"]
path_prefix = "/h2-quic"
upstream = "h2quic"
[[routes]]
name = "h2"
hosts = ["example.test"]
path_prefix = "/h2"
upstream = "h2"
[[routes]]
name = "closed-h2"
hosts = ["example.test"]
path_prefix = "/closed-h2"
upstream = "h2-closed"

[routes.timeouts]
upstream_request_timeout_ms = 15000
upstream_first_byte_timeout_ms = 15000
[[routes]]
name = "closed-h3"
hosts = ["example.test"]
path_prefix = "/closed-h3"
upstream = "h2-closed"

[routes.timeouts]
upstream_request_timeout_ms = 15000
upstream_first_byte_timeout_ms = 15000
[[routes]]
name = "h3"
hosts = ["example.test"]
path_prefix = "/h3"
upstream = "h3"
[[routes]]
name = "shaped"
hosts = ["example.test"]
path_prefix = "/shaped"
upstream = "h2"
[routes.bandwidth]
upload_bytes_per_second = 64
download_bytes_per_second = 64
EOF

if [[ -z "${OXIBELT_DOCKER_IMAGE:-}" ]]; then
  docker build --target standalone -t "${proxy_image}" -f "${repo_root}/source/ops/Dockerfile.alpine" "${repo_root}"
fi
if [[ -z "${OXIBELT_PROTOCOL_PROBE_IMAGE:-}" ]]; then
  docker build -t "${probe_image}" "${repo_root}/tests/docker/protocol_probe"
fi
docker network create "${network}" >/dev/null
for version in h2 h3; do
  command=webtransport-upstream
  if [[ "${version}" == h2 ]]; then command=webtransport-h2-upstream; fi
  name="${run_id}-upstream-${version}"
  docker create --name "${name}" --label "${label}" --network "${network}" \
    --network-alias "upstream-${version}" "${probe_image}" "${command}" \
    --listen 0.0.0.0:18443 --cert /tls/server.pem --key /tls/server.key --name "upstream-${version}" >/dev/null
  docker cp "${work_dir}/server.pem" "${name}:/tls/server.pem"
  docker cp "${work_dir}/server.key" "${name}:/tls/server.key"
  docker start "${name}" >/dev/null
done
name="${run_id}-upstream-h2-closed"
docker create --name "${name}" --label "${label}" --network "${network}" \
  --network-alias upstream-h2-closed "${probe_image}" webtransport-h2-upstream \
  --listen 0.0.0.0:18443 --cert /tls/server.pem --key /tls/server.key \
  --name upstream-h2-closed --close-before-connect >/dev/null
docker cp "${work_dir}/server.pem" "${name}:/tls/server.pem"
docker cp "${work_dir}/server.key" "${name}:/tls/server.key"
docker start "${name}" >/dev/null
name="${run_id}-upstream-h2-quic"
docker create --name "${name}" --label "${label}" --network "${network}" \
  --network-alias upstream-h2-quic "${probe_image}" webtransport-h2-upstream \
  --listen 0.0.0.0:18443 --cert /tls/server.pem --key /tls/server.key \
  --name upstream-h2-quic --reset-prefix optional >/dev/null
docker cp "${work_dir}/server.pem" "${name}:/tls/server.pem"
docker cp "${work_dir}/server.key" "${name}:/tls/server.key"
docker start "${name}" >/dev/null
docker create --name "${run_id}-proxy" --label "${label}" --network "${network}" \
  --network-alias proxy -e OXIBELT_ADMIN_TOKEN=webtransport-integration-only \
  "${proxy_image}" >/dev/null
docker cp "${work_dir}/oxibelt.toml" "${run_id}-proxy:/etc/oxibelt/config/oxibelt.toml"
for file in server.pem server.key ca.pem; do
  tar --create --file - --owner=10001 --group=10001 --mode=0440 -C "${work_dir}" "${file}" \
    | docker cp -a - "${run_id}-proxy:/etc/oxibelt/cert/"
done
docker start "${run_id}-proxy" >/dev/null

probe() {
  local probe_name="${run_id}-probe-${BASHPID}-${RANDOM}"
  local status=0
  docker create --name "${probe_name}" --label "${label}" --network "${network}" \
    "${probe_image}" "$@" >/dev/null
  docker cp "${work_dir}/ca.pem" "${probe_name}:/tls/ca.pem"
  docker start -a "${probe_name}" || status=$?
  docker rm -f "${probe_name}" >/dev/null
  return "${status}"
}

prompt_probe() {
  local description="$1"
  local max_seconds="$2"
  shift 2
  local probe_name="${run_id}-prompt-probe-${BASHPID}-${RANDOM}"
  local output status=0
  docker create --name "${probe_name}" --label "${label}" --network "${network}" \
    --entrypoint /bin/sleep "${probe_image}" 60 >/dev/null
  docker cp "${work_dir}/ca.pem" "${probe_name}:/tls/ca.pem"
  docker start "${probe_name}" >/dev/null
  output="$(timeout --signal=KILL "${max_seconds}s" docker exec "${probe_name}" \
    /usr/local/bin/protocol-probe "$@")" || status=$?
  docker rm -f "${probe_name}" >/dev/null
  if ((status != 0)); then
    printf '%s\n' "${output}" >&2
    if ((status == 124 || status == 137)); then
      echo "${description} did not complete within ${max_seconds}s" >&2
    fi
    return "${status}"
  fi
  printf '%s\n' "${output}"
}

ready=0
for ((attempt=0; attempt<30; attempt++)); do
  if probe webtransport-h2-client --host proxy --port 8443 --server-name proxy \
      --authority example.test --path /h2/session --ca-cert /tls/ca.pem --scenario echo \
      >"${work_dir}/ready.log" 2>&1; then ready=1; break; fi
  sleep 1
done
if [[ "${ready}" != 1 ]]; then cat "${work_dir}/ready.log"; exit 1; fi
echo "HTTP/2 downstream to closed HTTP/2 upstream fails before first-byte timeout"
prompt_probe "HTTP/2 downstream to closed HTTP/2 upstream" 5 \
  webtransport-h2-client --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /closed-h2/session --ca-cert /tls/ca.pem --scenario echo \
  --expect-status 502
echo "HTTP/2 downstream to HTTP/2 upstream remains healthy after the closed route"
probe webtransport-h2-client --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /h2/session --ca-cert /tls/ca.pem --scenario echo \
  --reset-prefix required
echo "HTTP/3 downstream to closed HTTP/2 upstream fails before first-byte timeout"
prompt_probe "HTTP/3 downstream to closed HTTP/2 upstream" 5 \
  webtransport-multiplex --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /closed-h3/session --ca-cert /tls/ca.pem \
  --sessions 1 --expect-statuses 502
echo "HTTP/3 downstream to HTTP/2 upstream remains healthy after the closed route"
probe webtransport-multiplex --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /h2-quic/session --ca-cert /tls/ca.pem \
  --sessions 1 --expect-statuses 200
echo "HTTP/2 downstream to HTTP/2 upstream"
probe webtransport-h2-client --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /h2/session --ca-cert /tls/ca.pem --scenario echo \
  --reset-prefix required
echo "HTTP/3 downstream to HTTP/2 upstream"
probe webtransport-multiplex --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /h2-quic/session --ca-cert /tls/ca.pem \
  --sessions 1 --expect-statuses 200
echo "HTTP/2 downstream to HTTP/3 upstream"
probe webtransport-h2-client --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /h3/session --ca-cert /tls/ca.pem --scenario echo \
  --reset-prefix optional
echo "HTTP/3 downstream to HTTP/3 upstream"
probe webtransport-multiplex --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /h3/session --ca-cert /tls/ca.pem \
  --sessions 1 --expect-statuses 200
echo "HTTP/2 WebTransport request WAF denial"
probe webtransport-h2-client --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /h2/blocked --ca-cert /tls/ca.pem \
  --scenario echo --expect-status 403
echo "HTTP/2 WebTransport request WAF silent close"
probe webtransport-h2-client --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /closed-h2/silent-close --ca-cert /tls/ca.pem \
  --scenario silent-close
echo "HTTP/2 WebTransport stream-phase WAF close"
probe webtransport-h2-client --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /h2/session --ca-cert /tls/ca.pem --scenario waf-payload
echo "HTTP/2 WebTransport configured bandwidth shaping"
probe webtransport-h2-client --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /shaped/session --ca-cert /tls/ca.pem --scenario shaped
for scenario in malformed truncated oversized flow-violation stream-limit zero-window-reset sibling-isolation; do
  echo "HTTP/2 WebTransport negative conformance: ${scenario}"
  probe webtransport-h2-client --host proxy --port 8443 --server-name proxy \
    --authority example.test --path /h2/session --ca-cert /tls/ca.pem --scenario "${scenario}"
done
echo "Admin HTTP/2 over TLS 1.2 suppresses WebTransport SETTINGS"
probe webtransport-h2-client --host proxy --port 9092 --server-name proxy \
  --authority proxy:9092 --path /admin/v1/operations --ca-cert /tls/ca.pem \
  --tls-version tls1.2 --scenario tls12-setting-suppression
echo "Admin HTTP/2 authentication and operation events"
admin_args=(--protocol h2 --host proxy --port 9092 --server-name proxy \
  --authority proxy:9092 --ca-cert /tls/ca.pem)
probe downstream "${admin_args[@]}" --path /admin/v1/operations --expect-status 401
probe downstream "${admin_args[@]}" --path /admin/v1/operations --tls-version tls1.2 \
  --header 'authorization:Bearer webtransport-integration-only' --expect-status 200
created="$(probe downstream "${admin_args[@]}" --path /admin/v1/operations --method POST \
  --header 'authorization:Bearer webtransport-integration-only' \
  --header 'content-type:application/json' \
  --body '{"kind":"webtransport_snapshot","request":{}}' --expect-status 202)"
operation_id="$(jq -er '.body | fromjson | .id' <<<"${created}")"
for auth in missing valid; do
  auth_args=()
  expected=401
  if [[ "${auth}" == valid ]]; then
    auth_args=(--header 'authorization:Bearer webtransport-integration-only')
    expected=200
  fi
  probe webtransport-h2-client --host proxy --port 9092 --server-name proxy \
    --authority proxy:9092 --path "/admin/v1/operations/${operation_id}/events/wt" \
    --ca-cert /tls/ca.pem --scenario admin-events --expect-status "${expected}" "${auth_args[@]}"
done
for coding in br zstd gzip deflate; do
  probe webtransport-h2-client --host proxy --port 9092 --server-name proxy \
    --authority proxy:9092 --path "/admin/v1/operations/${operation_id}/events/wt" \
    --ca-cert /tls/ca.pem --scenario admin-events --expect-status 200 \
    --header 'authorization:Bearer webtransport-integration-only' --event-coding "${coding}"
done
probe webtransport-h2-client --host proxy --port 9092 --server-name proxy \
  --authority proxy:9092 --path "/admin/v1/operations/${operation_id}/events/wt" \
  --ca-cert /tls/ca.pem --scenario admin-events --expect-status 400 \
  --header 'authorization:Bearer webtransport-integration-only' \
  --header 'oxibelt-event-stream:ndjson-v1; coding=unsupported'
probe webtransport-h2-client --host proxy --port 9092 --server-name proxy \
  --authority proxy:9092 --path "/admin/v1/operations/${operation_id}/events/wt" \
  --ca-cert /tls/ca.pem --scenario admin-events --expect-status 403 \
  --header 'authorization:Bearer webtransport-integration-only' --header 'origin:https://other.test'
echo "Admin operation drains one active HTTP/2 WebTransport session"
drain_target="${run_id}-drain-target"
docker create --name "${drain_target}" --label "${label}" --network "${network}" \
  "${probe_image}" webtransport-h2-client --host proxy --port 8443 --server-name proxy \
  --authority example.test --path /h2/session --ca-cert /tls/ca.pem \
  --scenario admin-drain-target >/dev/null
docker cp "${work_dir}/ca.pem" "${drain_target}:/tls/ca.pem"
docker start "${drain_target}" >/dev/null
drain_ready=0
for ((attempt=0; attempt<50; attempt++)); do
  if docker logs "${drain_target}" 2>&1 | grep -q '"drain_target":"ready"'; then
    drain_ready=1
    break
  fi
  if [[ "$(docker inspect --format '{{.State.Running}}' "${drain_target}")" != true ]]; then
    docker logs "${drain_target}" 2>&1
    echo "Admin drain target exited before becoming ready" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "${drain_ready}" != 1 ]]; then
  docker logs "${drain_target}" 2>&1
  echo "Admin drain target did not become ready" >&2
  exit 1
fi
drain_created="$(probe downstream "${admin_args[@]}" --path /admin/v1/operations --method POST \
  --header 'authorization:Bearer webtransport-integration-only' \
  --header 'content-type:application/json' \
  --body '{"kind":"webtransport_drain","request":{"scope":{"route":"h2"},"grace_ms":100,"close_code":77,"reason":"bounded admin drain"}}' \
  --expect-status 202)"
drain_operation_id="$(jq -er '.body | fromjson | .id' <<<"${drain_created}")"
drain_exit="$(docker wait "${drain_target}")"
docker logs "${drain_target}" 2>&1
if [[ "${drain_exit}" != 0 ]]; then
  echo "Admin drain target failed with exit ${drain_exit}" >&2
  exit 1
fi
docker rm -f "${drain_target}" >/dev/null
drain_operation=""
for ((attempt=0; attempt<50; attempt++)); do
  drain_operation_response="$(probe downstream "${admin_args[@]}" \
    --path "/admin/v1/operations/${drain_operation_id}" \
    --header 'authorization:Bearer webtransport-integration-only' --expect-status 200)"
  drain_operation="$(jq -cer '.body | fromjson' <<<"${drain_operation_response}")"
  if [[ "$(jq -r '.state' <<<"${drain_operation}")" == succeeded ]]; then break; fi
  sleep 0.1
done
jq -e '.state == "succeeded" and .result.matched_sessions == 1 and .result.close_sent == 1 and .result.grace_ms == 100' \
  <<<"${drain_operation}" >/dev/null
probe webtransport-h2-client --host proxy --port 9092 --server-name proxy \
  --authority proxy:9092 --path "/admin/v1/operations/${drain_operation_id}/events/wt" \
  --ca-cert /tls/ca.pem --scenario admin-events --expect-status 200 \
  --header 'authorization:Bearer webtransport-integration-only'
echo "WebTransport H2/H3 and Admin TLS matrix passed"
