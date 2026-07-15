#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
run_id="$(date +%s)-$$"
work_dir="${repo_root}/tests/.tmp/remote-signer-${run_id}"
test_label="oxibelt.test.run=remote-signer-${run_id}"
socket_volume="oxibelt-keysigner-sock-${run_id}"
cert_volume="oxibelt-keysigner-cert-${run_id}"
signer_container="oxibelt-keysigner-${run_id}"
cert_seed_container="oxibelt-keysigner-cert-seed-${run_id}"
probe_container="oxibelt-keysigner-probe-${run_id}"
probe_image="oxibelt/keysigner-probe:${run_id}"
own_keysigner_image=0
keysigner_image="${OXIBELT_KEYSIGNER_DOCKER_IMAGE:-${OXIBELT_DOCKER_IMAGE:-}}"

if [[ -z "${keysigner_image}" ]]; then
  keysigner_image="oxibelt/keysigner-it:${run_id}"
  own_keysigner_image=1
fi

cleanup() {
  docker rm -f "${probe_container}" "${signer_container}" "${cert_seed_container}" >/dev/null 2>&1 || true
  docker volume rm "${socket_volume}" "${cert_volume}" >/dev/null 2>&1 || true
  docker rmi -f "${probe_image}" >/dev/null 2>&1 || true
  if [[ "${own_keysigner_image}" == "1" ]]; then
    docker rmi -f "${keysigner_image}" >/dev/null 2>&1 || true
  fi
  if [[ "${KEEP_TEST_ARTIFACTS:-0}" != "1" ]]; then
    rm -rf "${work_dir}"
  fi
}
trap cleanup EXIT

mkdir -p "${work_dir}"

token="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
key_path="${work_dir}/privkey.pem"
token_path="${work_dir}/keysigner-token.b64"
probe_path="${work_dir}/remote_signer_dos_probe.py"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${key_path}" >/dev/null 2>&1
chmod 0644 "${key_path}"
printf '%s\n' "${token}" >"${token_path}"
chmod 0644 "${token_path}"

cat >"${probe_path}" <<'PY'
import json
import os
import socket
import struct
import sys
import time

socket_path = os.environ["SIGNER_SOCKET"]
token = os.environ["OXIBELT_KEYSIGNER_TOKEN"]
attack_connections = int(os.environ.get("ATTACK_CONNECTIONS", "80"))


def recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("signer closed response early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def request_describe_key():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(2.0)
        sock.connect(socket_path)
        payload = json.dumps(
            {
                "type": "describe_key",
                "token": token,
                "key_id": "edge-default",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        sock.sendall(struct.pack(">I", len(payload)))
        sock.sendall(payload)
        response_len = struct.unpack(">I", recv_exact(sock, 4))[0]
        response = json.loads(recv_exact(sock, response_len))
        if response.get("type") != "describe_key":
            raise RuntimeError(f"unexpected describe_key response: {response!r}")
        if not response.get("schemes"):
            raise RuntimeError("describe_key response did not include signature schemes")
        return response


baseline = request_describe_key()
print(f"baseline describe_key schemes={len(baseline['schemes'])}")

idle_sockets = []
connect_errors = 0
for _ in range(attack_connections):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        sock.connect(socket_path)
    except OSError:
        connect_errors += 1
        sock.close()
        continue
    sock.settimeout(None)
    idle_sockets.append(sock)

time.sleep(1.0)

closed = 0
still_open = 0
for sock in idle_sockets:
    sock.settimeout(0.05)
    try:
        data = sock.recv(1)
        if data == b"":
            closed += 1
        else:
            still_open += 1
    except socket.timeout:
        still_open += 1
    except OSError:
        closed += 1
    finally:
        sock.close()

print(
    "idle attack connections: "
    f"opened={len(idle_sockets)} connect_errors={connect_errors} "
    f"closed_by_signer={closed} still_open={still_open}"
)

if still_open:
    sys.exit(f"{still_open} idle signer sockets remained open after the server deadline")

post_attack = request_describe_key()
print(f"post-attack describe_key schemes={len(post_attack['schemes'])}")
PY
chmod 0644 "${probe_path}"

if [[ "${own_keysigner_image}" == "1" ]]; then
  echo "Building OxiBelt keysigner image"
  docker build \
    --target keysigner \
    -t "${keysigner_image}" \
    -f "${repo_root}/source/ops/Dockerfile.alpine" \
    "${repo_root}" >/dev/null
fi

echo "Building remote signer probe image"
docker build \
  -t "${probe_image}" \
  -f "${repo_root}/tests/docker/mock_upstream/Dockerfile" \
  "${repo_root}/tests/docker/mock_upstream" >/dev/null

docker volume create --label "${test_label}" "${socket_volume}" >/dev/null
docker volume create --label "${test_label}" "${cert_volume}" >/dev/null
docker create \
  --name "${cert_seed_container}" \
  --label "${test_label}" \
  --user 0:0 \
  --mount "type=volume,src=${cert_volume},dst=/cert" \
  --entrypoint sh \
  "${probe_image}" \
  -c 'chown 10002:10002 /cert /cert/privkey.pem /cert/keysigner-token.b64 && chmod 0550 /cert && chmod 0400 /cert/privkey.pem /cert/keysigner-token.b64' >/dev/null
docker cp "${key_path}" "${cert_seed_container}:/cert/privkey.pem"
docker cp "${token_path}" "${cert_seed_container}:/cert/keysigner-token.b64"
docker start -a "${cert_seed_container}" >/dev/null
docker rm "${cert_seed_container}" >/dev/null
docker run --rm \
  --label "${test_label}" \
  --user 0:0 \
  --mount "type=volume,src=${socket_volume},dst=/sock" \
  --entrypoint sh \
  "${probe_image}" \
  -c 'chown 10002:10002 /sock && chmod 0770 /sock'

docker create \
  --name "${signer_container}" \
  --label "${test_label}" \
  --user 10002:10002 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --ulimit nofile=64:64 \
  --mount "type=volume,src=${socket_volume},dst=/sock" \
  --mount "type=volume,src=${cert_volume},dst=/etc/oxibelt/cert,readonly" \
  --entrypoint /usr/local/bin/oxibelt-keysigner \
  "${keysigner_image}" \
  --socket /sock/sign.sock \
  --key edge-default=/etc/oxibelt/cert/privkey.pem \
  --token-file /etc/oxibelt/cert/keysigner-token.b64 \
  --token-reload-interval-ms 1000 \
  --socket-mode 0660 \
  --allow-peer-uid 10001 \
  --max-connections 4 \
  --io-timeout-ms 200 >/dev/null

docker start "${signer_container}" >/dev/null

for _ in $(seq 1 100); do
  if docker run --rm \
    --mount "type=volume,src=${socket_volume},dst=/sock" \
    --entrypoint sh \
    "${probe_image}" -c 'test -S /sock/sign.sock' >/dev/null 2>&1; then
    break
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "${signer_container}" 2>/dev/null || echo false)" != "true" ]]; then
    docker logs "${signer_container}" >&2 || true
    echo "remote signer exited before creating its socket" >&2
    exit 1
  fi
  sleep 0.05
done

if ! docker run --rm \
  --mount "type=volume,src=${socket_volume},dst=/sock" \
  --entrypoint sh \
  "${probe_image}" -c 'test -S /sock/sign.sock' >/dev/null 2>&1; then
  docker logs "${signer_container}" >&2 || true
  echo "remote signer socket was not created" >&2
  exit 1
fi

docker create \
  --name "${probe_container}" \
  --label "${test_label}" \
  --user 10001:10001 \
  --group-add 10002 \
  --mount "type=volume,src=${socket_volume},dst=/sock" \
  --env "OXIBELT_KEYSIGNER_TOKEN=${token}" \
  --env "SIGNER_SOCKET=/sock/sign.sock" \
  --env "ATTACK_CONNECTIONS=80" \
  "${probe_image}" \
  python /tmp/remote_signer_dos_probe.py >/dev/null

docker cp "${probe_path}" "${probe_container}:/tmp/remote_signer_dos_probe.py"
docker start -a "${probe_container}"

if [[ "$(docker inspect -f '{{.State.Running}}' "${signer_container}" 2>/dev/null || echo false)" != "true" ]]; then
  docker logs "${signer_container}" >&2 || true
  echo "remote signer exited during the slowloris regression test" >&2
  exit 1
fi

echo "Remote signer slowloris Docker integration passed"
