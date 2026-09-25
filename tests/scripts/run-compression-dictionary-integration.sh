#!/usr/bin/env bash
# RFC 9842 dictionary coding matrix over real TLS and QUIC listeners.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
run_id="dictionary-$(date +%s)-$$"
work_dir="$(mktemp -d)"
network="oxibelt-${run_id}"
label="oxibelt.test.run=${run_id}"
proxy_image="${OXIBELT_DOCKER_IMAGE:-oxibelt/proxy:${run_id}}"
probe_image="${OXIBELT_PROTOCOL_PROBE_IMAGE:-oxibelt/protocol-probe:${run_id}}"
fixture="${repo_root}/tests/docker/compression_dictionary/raw-dictionary.txt"
payload='RFC 9842 dictionary coding integration payload'

cleanup() {
  local status=$?
  if ((status != 0)); then
    for name in proxy origin-h1 origin-h2 origin-h3; do
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

[[ -s "${fixture}" && ! -L "${fixture}" ]] || { echo "dictionary fixture is not a nonempty regular file" >&2; exit 1; }
dictionary_sha256="$(sha256sum "${fixture}" | awk '{print $1}')"
readonly dictionary_sha256

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 1 \
  -subj '/CN=OxiBelt dictionary test CA' -addext 'basicConstraints=critical,CA:TRUE' \
  -keyout "${work_dir}/ca.key" -out "${work_dir}/ca.pem" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
  -subj '/CN=proxy' -keyout "${work_dir}/server.key" -out "${work_dir}/server.csr" >/dev/null 2>&1
cat >"${work_dir}/extensions.cnf" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:proxy,DNS:origin-h1,DNS:origin-h2,DNS:origin-h3
EOF
openssl x509 -req -in "${work_dir}/server.csr" -CA "${work_dir}/ca.pem" -CAkey "${work_dir}/ca.key" \
  -CAcreateserial -days 1 -sha256 -extfile "${work_dir}/extensions.cnf" -out "${work_dir}/server.pem" >/dev/null 2>&1
for identity in client wrong-client; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
    -subj "/CN=${identity}" -keyout "${work_dir}/${identity}.key" -out "${work_dir}/${identity}.csr" >/dev/null 2>&1
  cat >"${work_dir}/${identity}.cnf" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
  openssl x509 -req -in "${work_dir}/${identity}.csr" -CA "${work_dir}/ca.pem" -CAkey "${work_dir}/ca.key" \
    -CAcreateserial -days 1 -sha256 -extfile "${work_dir}/${identity}.cnf" -out "${work_dir}/${identity}.pem" >/dev/null 2>&1
done

cat >"${work_dir}/oxibelt.toml" <<EOF
[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = false
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
[tls.client_auth]
mode = "optional"
ca_certs = ["ca.pem"]
[tls.ocsp]
mode = "disabled"
[proxy]
trusted_ca_certs = ["ca.pem"]
[cache]
enabled = true
store = "memory"
memory_max_size_bytes = 8388608
[compression]
enabled = true
min_size_bytes = 1
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"
[[waf.rules]]
name = "observe-decoded-dictionary-request"
phase = "request"
priority = 10
when = "Request.Http.Path.endsWith('/request-decode') && Request.Body.contains('inbound dictionary payload')"
[[waf.rules.actions]]
type = "set_request_header"
name = "x-waf-dictionary-decoded"
value = "yes"
[[waf.rules]]
name = "reject-decoded-managed-dictionary-upload"
phase = "request"
priority = 20
when = "Request.Http.Path.startsWith('/managed-reject') && Request.Body.contains('hello world')"
[[waf.rules.actions]]
type = "reject"
status = 403
body = "decoded managed dictionary upload rejected"

[compression_dictionary]
enabled = true
[[compression_dictionary.dictionaries]]
name = "downstream"
path = "raw-dictionary.txt"
sha256 = "${dictionary_sha256}"
public = true
url = "https://example.test:8443/dictionary.raw"
[[compression_dictionary.dictionaries]]
name = "origin-h1"
path = "raw-dictionary.txt"
sha256 = "${dictionary_sha256}"
public = true
url = "https://origin-h1:18443/dictionary.raw"
[[compression_dictionary.dictionaries]]
name = "origin-h2"
path = "raw-dictionary.txt"
sha256 = "${dictionary_sha256}"
public = true
url = "https://origin-h2:18443/dictionary.raw"
[[compression_dictionary.dictionaries]]
name = "origin-h3"
path = "raw-dictionary.txt"
sha256 = "${dictionary_sha256}"
public = true
url = "https://origin-h3:18443/dictionary.raw"
[[compression_dictionary.stores]]
name = "memory"
kind = "memory"
quota_bytes = 1048576
[[compression_dictionary.profiles]]
name = "dictionary"
downstream = true
upstream = true
request_decode = true
store = "memory"
dictionaries = ["downstream", "origin-h1", "origin-h2", "origin-h3"]
max_dictionary_bytes = 1048576
max_dictionaries = 4
max_total_dictionary_bytes = 1048576
max_pending_dictionary_bytes = 1048576
max_codec_concurrency = 2
max_codec_memory_bytes = 1073741824
max_decoded_size_bytes = 1048576
max_expansion_ratio = 16
codec_timeout_ms = 10000
[compression_dictionary.profiles.advertise]
match = "/*"
id = "test-dict"

[[upload_stores]]
name = "managed-dictionary-local"
kind = "local"
[upload_stores.local]
root = "/tmp/managed-dictionary-store"
[[upload_profiles]]
name = "managed-dictionary"
store = "managed-dictionary-local"
public_base_url = "https://example.test:8443/"
control_path_prefix = "/managed/uploads"
object_path_prefix = "/managed/objects"
staging_dir = "/tmp/managed-dictionary-staging"
max_staging_bytes = 1048576
max_upload_bytes = 1048576
max_part_bytes = 1048576
inspection_bytes = 1048576
max_storage_bytes = 2097152
max_sessions = 32
max_parts = 8
max_concurrent_uploads = 4
max_concurrent_parts = 4
ttl_seconds = 60
object_ttl_seconds = 60
destination = { kind = "object" }
identity = { kind = "mtls", source = "dictionary-test-ca" }
[upload_profiles.compression_dictionary]
profile = "dictionary"
dictionary = "downstream"
[[upload_profiles]]
name = "managed-dictionary-reject"
store = "managed-dictionary-local"
public_base_url = "https://example.test:8443/"
control_path_prefix = "/managed-reject/uploads"
object_path_prefix = "/managed-reject/objects"
staging_dir = "/tmp/managed-dictionary-staging"
max_staging_bytes = 1048576
max_upload_bytes = 1048576
max_part_bytes = 1048576
inspection_bytes = 1048576
max_storage_bytes = 2097152
max_sessions = 32
max_parts = 8
max_concurrent_uploads = 4
max_concurrent_parts = 4
ttl_seconds = 60
object_ttl_seconds = 60
destination = { kind = "object" }
identity = { kind = "mtls", source = "dictionary-test-ca" }
[upload_profiles.compression_dictionary]
profile = "dictionary"
dictionary = "downstream"

[[upstreams]]
name = "origin-h1"
origin = "https://origin-h1:18443"
max_http_version = "h1"
[upstreams.tls.ech]
mode = "disabled"
[[upstreams]]
name = "origin-h2"
origin = "https://origin-h2:18443"
max_http_version = "h2"
[upstreams.tls.ech]
mode = "disabled"
[[upstreams]]
name = "origin-h3"
origin = "https://origin-h3:18443"
max_http_version = "h3"
[upstreams.tls.ech]
mode = "disabled"

[[routes]]
name = "origin-h1"
hosts = ["example.test"]
path_prefix = "/h1"
upstream = "origin-h1"
cache = "default"
compression_dictionary_profile = "dictionary"
[[routes]]
name = "serve-downstream-dictionary"
hosts = ["example.test"]
path_prefix = "/dictionary.raw"
dictionary = "downstream"
compression_dictionary_profile = "dictionary"
[[routes]]
name = "origin-h2"
hosts = ["example.test"]
path_prefix = "/h2"
upstream = "origin-h2"
cache = "default"
compression_dictionary_profile = "dictionary"
[routes.actions.request_headers]
remove = ["authorization", "cookie"]
[[routes]]
name = "origin-h3"
hosts = ["example.test"]
path_prefix = "/h3"
upstream = "origin-h3"
cache = "default"
compression_dictionary_profile = "dictionary"
[[routes]]
name = "managed-dictionary"
hosts = ["example.test"]
path_prefix = "/managed"
resumable_upload = "managed-dictionary"
[routes.match.tls.client_cert]
present = true
[[routes]]
name = "managed-dictionary-reject"
hosts = ["example.test"]
path_prefix = "/managed-reject"
resumable_upload = "managed-dictionary-reject"
[routes.match.tls.client_cert]
present = true
EOF

if [[ -z "${OXIBELT_DOCKER_IMAGE:-}" ]]; then
  docker build --target standalone -t "${proxy_image}" -f "${repo_root}/source/ops/Dockerfile.alpine" "${repo_root}"
fi
if [[ -z "${OXIBELT_PROTOCOL_PROBE_IMAGE:-}" ]]; then
  docker build -t "${probe_image}" -f "${repo_root}/tests/docker/protocol_probe/Dockerfile" "${repo_root}"
fi
docker network create "${network}" >/dev/null

origin() {
  local protocol="$1" coding="$2"
  local name="${run_id}-origin-${protocol}"
  docker create --name "${name}" --label "${label}" --network "${network}" --network-alias "origin-${protocol}" \
    "${probe_image}" dictionary-origin --protocol "${protocol}" --listen 0.0.0.0:18443 \
    --cert /tls/server.pem --key /tls/server.key --dictionary /fixture/raw-dictionary.txt --coding "${coding}" >/dev/null
  docker cp "${work_dir}/server.pem" "${name}:/tls/server.pem"
  docker cp "${work_dir}/server.key" "${name}:/tls/server.key"
  docker cp "${fixture}" "${name}:/fixture/raw-dictionary.txt"
  docker start "${name}" >/dev/null
}
origin h1 dcb
origin h2 dcz
origin h3 dcb

docker create --name "${run_id}-proxy" --label "${label}" --network "${network}" --network-alias proxy \
  --tmpfs /tmp/managed-dictionary-staging:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001,mode=0700 \
  --ulimit stack=67108864:67108864 "${proxy_image}" >/dev/null
docker cp "${work_dir}/oxibelt.toml" "${run_id}-proxy:/etc/oxibelt/config/oxibelt.toml"
docker cp "${fixture}" "${run_id}-proxy:/etc/oxibelt/config/raw-dictionary.txt"
for file in server.pem server.key ca.pem; do
  tar --create --file - --owner=10001 --group=10001 --mode=0440 -C "${work_dir}" "${file}" | docker cp -a - "${run_id}-proxy:/etc/oxibelt/cert/"
done
docker start "${run_id}-proxy" >/dev/null

probe() {
  local name="${run_id}-probe-${BASHPID}-${RANDOM}" status=0
  docker create --name "${name}" --label "${label}" --network "${network}" "${probe_image}" "$@" >/dev/null
  docker cp "${work_dir}/ca.pem" "${name}:/tls/ca.pem"
  docker cp "${fixture}" "${name}:/fixture/raw-dictionary.txt"
  for file in client.pem client.key wrong-client.pem wrong-client.key; do
    docker cp "${work_dir}/${file}" "${name}:/tls/${file}"
  done
  docker start -a "${name}" || status=$?
  docker rm -f "${name}" >/dev/null
  return "${status}"
}

ready=0
for ((attempt=0; attempt<30; attempt++)); do
  if probe dictionary-client --protocol h2 --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
      --path /h2/ready --ca-cert /tls/ca.pem --dictionary /fixture/raw-dictionary.txt --expect-body "${payload}" --expect-coding dcz; then ready=1; break; fi
  sleep 1
done
((ready == 1)) || { echo "proxy did not become dictionary-ready" >&2; exit 1; }

for ingress in h1 h2 h3; do
  for upstream in h1 h2 h3; do
    coding=dcb
    [[ "${upstream}" == h2 ]] && coding=dcz
    echo "RFC 9842 ${ingress} ingress to ${upstream} upstream"
    probe dictionary-client --protocol "${ingress}" --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
      --path "/${upstream}/matrix-${ingress}" --ca-cert /tls/ca.pem --dictionary /fixture/raw-dictionary.txt \
      --expect-body "${payload}" --expect-coding "${coding}"
  done
done

echo "RFC 9842 cache dictionary representation identity"
probe dictionary-client --protocol h2 --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
  --path /h2/cached --ca-cert /tls/ca.pem --dictionary /fixture/raw-dictionary.txt --expect-body "${payload}" --expect-coding dcz --expect-origin-count 1
probe dictionary-client --protocol h3 --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
  --path /h2/cached --ca-cert /tls/ca.pem --dictionary /fixture/raw-dictionary.txt --expect-body "${payload}" --expect-coding dcz --expect-origin-count 1

echo "RFC 9842 cache revalidation retains the exact dictionary representation"
probe dictionary-client --protocol h1 --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
  --path /h1/revalidate --ca-cert /tls/ca.pem --dictionary /fixture/raw-dictionary.txt --expect-body "${payload}" --expect-coding dcb --expect-origin-count 1
probe dictionary-client --protocol h2 --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
  --path /h1/revalidate --ca-cert /tls/ca.pem --dictionary /fixture/raw-dictionary.txt --expect-body "${payload}" --expect-coding dcb --expect-origin-count 2

echo "RFC 9842 missing downstream dictionary does not select a representation"
probe dictionary-client --protocol h3 --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
  --path /h3/missing --ca-cert /tls/ca.pem --dictionary /fixture/raw-dictionary.txt --expect-body "${payload}" --expect-plain --missing-dictionary

for ingress in h1 h2 h3; do
  coding=dcb
  [[ "${ingress}" == h2 ]] && coding=dcz
  echo "RFC 9842 ${ingress} dictionary request decode before WAF"
  probe dictionary-client --protocol "${ingress}" --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
    --path "/h1/request-decode" --ca-cert /tls/ca.pem --dictionary /fixture/raw-dictionary.txt \
    --expect-body 'request decode ok' --expect-plain --request-coding "${coding}" --request-body 'inbound dictionary payload'
done

echo "RFC 9842 public-request guard strips upstream negotiation for credentialed traffic"
probe dictionary-client --protocol h1 --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
  --path /h2/private --ca-cert /tls/ca.pem --dictionary /fixture/raw-dictionary.txt --expect-body "${payload}" --expect-plain --private-request

for ingress in h1 h2 h3; do
  for coding in dcb dcz; do
    echo "RFC 9842 managed upload ${ingress} ${coding} encoded-offset lifecycle"
    probe managed-upload-client --protocol "${ingress}" --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
      --creation-path /managed/submit --ca-cert /tls/ca.pem --client-cert /tls/client.pem --client-key /tls/client.key \
      --wrong-client-cert /tls/wrong-client.pem --wrong-client-key /tls/wrong-client.key \
      --dictionary /fixture/raw-dictionary.txt --coding "${coding}"
  done
done

echo "RFC 9842 managed upload decoded WAF rejection is terminal"
probe managed-upload-client --protocol h2 --host proxy --port 8443 --server-name proxy --authority example.test:8443 \
  --creation-path /managed-reject/submit --ca-cert /tls/ca.pem --client-cert /tls/client.pem --client-key /tls/client.key \
  --wrong-client-cert /tls/wrong-client.pem --wrong-client-key /tls/wrong-client.key \
  --dictionary /fixture/raw-dictionary.txt --coding dcz --expect-terminal-waf

echo "RFC 9842 H1/H2/H3 ingress-upstream matrix passed"
