#!/usr/bin/env bash
# Focused RFC 9846 server-side probes against a disposable OxiBelt listener.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
run_id="tlsfuzzer-$(date +%s)-$$"
work_dir="$(mktemp -d)"
network="oxibelt-${run_id}"
label="oxibelt.test.run=${run_id}"
proxy_image="${OXIBELT_DOCKER_IMAGE:-oxibelt/proxy:${run_id}}"
upstream_image="${OXIBELT_MOCK_UPSTREAM_IMAGE:-oxibelt/mock-upstream:${run_id}}"
fuzzer_image="oxibelt/tlsfuzzer:${run_id}"
openssl_image="rust:1.98.1-trixie@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546"
proxy_container="${run_id}-proxy"

cleanup() {
  local status=$?
  if ((status != 0)) && docker container inspect "${proxy_container}" >/dev/null 2>&1; then
    docker logs "${proxy_container}" 2>&1 | tail -100 || true
  fi
  docker ps -aq --filter "label=${label}" | xargs -r docker rm -fv >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  docker image rm "${fuzzer_image}" >/dev/null 2>&1 || true
  if [[ -z "${OXIBELT_DOCKER_IMAGE:-}" ]]; then docker image rm "${proxy_image}" >/dev/null 2>&1 || true; fi
  if [[ -z "${OXIBELT_MOCK_UPSTREAM_IMAGE:-}" ]]; then docker image rm "${upstream_image}" >/dev/null 2>&1 || true; fi
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT

# Commit objects and the base image digest pin every executable dependency.
# Fetching the commit directly also fails closed if the remote removes it.
fetch_tree() {
  local name="$1" repository="$2" revision="$3"
  local tree="${work_dir}/image/${name}"
  git init -q "${tree}"
  git -C "${tree}" remote add origin "https://github.com/${repository}.git"
  git -C "${tree}" fetch --quiet --depth=1 origin "${revision}"
  git -C "${tree}" checkout --quiet --detach FETCH_HEAD
  [[ "$(git -C "${tree}" rev-parse HEAD)" == "${revision}" ]]
  rm -rf -- "${tree}/.git"
}

mkdir -p "${work_dir}/image"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=proxy' -addext 'subjectAltName=DNS:proxy,DNS:tls12.proxy' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "${work_dir}/server.key" -out "${work_dir}/server.pem" >/dev/null 2>&1
cp "${work_dir}/server.pem" "${work_dir}/image/server.pem"
fetch_tree tlsfuzzer tlsfuzzer/tlsfuzzer 5eebc4464e5197a7f7392fb9acda99cfc32441f7
fetch_tree tlslite-ng tlsfuzzer/tlslite-ng 7e95ea1a86c0d42d8d931ff14134d31f01ce1d76
fetch_tree ecdsa warner/python-ecdsa bff40c6cf2340148d410d5b3def0e949c547caf1
fetch_tree six benjaminp/six c8e394065cd541a16c040515dc0afb85cf22a7c3
cp "${repo_root}/tests/docker/tlsfuzzer/Dockerfile" "${work_dir}/image/Dockerfile"
cp "${repo_root}/tests/docker/tlsfuzzer/h1_close_notify.py" "${work_dir}/image/h1_close_notify.py"
docker build -q -t "${fuzzer_image}" "${work_dir}/image" >/dev/null

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
http2 = false
http3 = false
[tls]
cert_chain = "server.pem"
private_key = "server.key"
min_version = "tls1.2"
max_version = "tls1.3"
[tls.ocsp]
mode = "disabled"
[proxy]
trusted_ca_certs = []
[proxy.auto_upgrade]
enabled = false
max_http_version = "h1"
[waf]
enabled = false
mode = "enforcing"
fail_policy = "closed"
[[upstreams]]
name = "http-upstream"
origin = "http://upstream:18080/"
max_http_version = "h1"
[[routes]]
name = "main"
hosts = ["proxy"]
path_prefix = "/"
upstream = "http-upstream"
[[routes]]
name = "tls12"
hosts = ["tls12.proxy"]
path_prefix = "/"
upstream = "http-upstream"
[routes.tls]
max_version = "tls1.2"
EOF

if [[ -z "${OXIBELT_DOCKER_IMAGE:-}" ]]; then
  docker build --target standalone -t "${proxy_image}" \
    -f "${repo_root}/source/ops/Dockerfile.alpine" "${repo_root}"
fi
if [[ -z "${OXIBELT_MOCK_UPSTREAM_IMAGE:-}" ]]; then
  docker build -t "${upstream_image}" "${repo_root}/tests/docker/mock_upstream"
fi

docker network create "${network}" >/dev/null
docker run -d --name "${run_id}-upstream" --label "${label}" \
  --network "${network}" --network-alias upstream -e LISTEN_PORT=18080 \
  "${upstream_image}" >/dev/null
docker create --name "${proxy_container}" --label "${label}" \
  --network "${network}" --network-alias proxy \
  "${proxy_image}" >/dev/null
docker cp "${work_dir}/oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
for file in server.pem server.key; do
  tar --create --file - --owner=10001 --group=10001 --mode=0440 \
    -C "${work_dir}" "${file}" | docker cp -a - "${proxy_container}:/etc/oxibelt/cert/"
done
docker start "${proxy_container}" >/dev/null

ready=0
for _ in $(seq 1 30); do
  if docker run --rm --network "${network}" "${fuzzer_image}" -c \
    'import socket; socket.create_connection(("proxy", 8443), 1).close()' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" != 1 ]]; then
  echo "OxiBelt TLS listener did not become ready" >&2
  exit 1
fi

# Run OpenSSL inside the same private Docker network. The image is already
# pinned by the repository's release-image builder, and needs no packages.
run_openssl_client() {
  local server_name="$1"
  shift
  local client_name="${run_id}-openssl-${RANDOM}" output status
  docker create --name "${client_name}" --label "${label}" \
    --network "${network}" -e "TLS_TEST_SERVER_NAME=${server_name}" \
    --entrypoint sh "${openssl_image}" -c '
      printf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" "$TLS_TEST_SERVER_NAME" |
        timeout 10s openssl s_client -connect proxy:8443 \
          -servername "$TLS_TEST_SERVER_NAME" -verify_hostname "$TLS_TEST_SERVER_NAME" \
          -CAfile /tmp/server.pem -verify_return_error -ign_eof -brief "$@"
    ' sh "$@" >/dev/null
  docker cp "${work_dir}/server.pem" "${client_name}:/tmp/server.pem"
  output="$(docker start -a "${client_name}" 2>&1)"
  status="$(docker inspect --format '{{.State.ExitCode}}' "${client_name}")"
  if [[ "${status}" != 0 ]]; then
    printf '%s\n' "${output}" >&2
    return "${status}"
  fi
  printf '%s\n' "${output}"
}

# Check both configured version policies with a normal OpenSSL client.
openssl_probe() {
  local server_name="$1" expected_protocol="$2"
  local output
  output="$(run_openssl_client "${server_name}" -min_protocol TLSv1.2 -max_protocol TLSv1.3)"
  if ! grep -Fq "Protocol version: ${expected_protocol}" <<<"${output}" ||
     ! grep -Fq 'Verification: OK' <<<"${output}" ||
     ! grep -Fq 'HTTP/1.1 ' <<<"${output}"; then
    printf '%s\n' "${output}" >&2
    return 1
  fi
  echo "OpenSSL ${server_name}: ${expected_protocol}, certificate verified, HTTP response received"
}
openssl_probe proxy TLSv1.3
openssl_probe tls12.proxy TLSv1.2

# Explicit names keep the run bounded even when upstream adds new scenarios.
run_probe() {
  local script="$1"
  shift
  echo "TLSfuzzer: ${script}: $*"
  docker run --rm --network "${network}" "${fuzzer_image}" \
    "scripts/${script}" -h proxy -p 8443 "$@"
}

run_probe test-tls13-version-negotiation.py \
  sanity 'tls 1.8 only' 'SSL 3.0 in supported version'
run_probe test-tls13-invalid-ciphers.py \
  sanity 'non-existing cipher 0x1306 with valid one' 'only invalid cipher 0x1306'
run_probe test-tls13-ccs.py \
  sanity 'both client and server send CCS' \
  'CCS message after Finished message' 'two byte long CCS'

echo 'TLS 1.3 HTTP/1.1 fast-path close_notify'
docker run --rm --network "${network}" "${fuzzer_image}" \
  /opt/probes/h1_close_notify.py

# Force TLS 1.2 against the dual-version default policy and inspect its raw
# ServerHello.random. RFC 9846 retains the RFC 8446 DOWNGRD\x01 requirement
# when a TLS 1.3-capable server negotiates TLS 1.2.
if ! run_openssl_client proxy -tls1_2 -msg \
  >"${work_dir}/downgrade-wire.log"; then
  tail -100 "${work_dir}/downgrade-wire.log" >&2
  exit 1
fi
python3 - "${work_dir}/downgrade-wire.log" <<'PY'
import pathlib
import re
import sys

trace = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
match = re.search(
    r"^<<< TLS [^\n]+, Handshake \[length [^]]+\], ServerHello\n"
    r"((?:[ \t]+(?:[0-9a-f]{2}[ \t]*)+\n)+)",
    trace,
    re.MULTILINE,
)
if not match:
    raise SystemExit("OpenSSL trace has no complete ServerHello")
hello = bytes.fromhex(match.group(1))
if len(hello) < 38 or hello[0] != 2 or int.from_bytes(hello[1:4], "big") + 4 != len(hello):
    raise SystemExit("OpenSSL trace has malformed ServerHello")
if hello[4:6] != b"\x03\x03" or hello[30:38] != b"DOWNGRD\x01":
    raise SystemExit(
        "dual-version TLS 1.2 ServerHello lacks the downgrade sentinel "
        f"(random suffix: {hello[30:38].hex()})"
    )
if "Protocol version: TLSv1.2" not in trace or "Verification: OK" not in trace:
    raise SystemExit("OpenSSL TLS 1.2 handshake or certificate verification failed")
print("dual-version TLS 1.2 ServerHello has the RFC 9846 downgrade sentinel")
PY
