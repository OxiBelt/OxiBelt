run_case_checks() {
  local baseline after_create after_expire create_delta expire_delta
  local load_container load_log load_pid
  local observed_create=0 observed_expire=0

  wait_for_udp_turn_echo
  baseline="$(proxy_socket_fd_count)"
  assert_socket_fd_count "${baseline}" "baseline"

  assert_udp_round_trip
  start_udp_session_load 32 load_container load_pid load_log
  after_create="${baseline}"
  for _ in $(seq 1 40); do
    after_create="$(proxy_socket_fd_count)"
    assert_socket_fd_count "${after_create}" "active load"
    create_delta=$((after_create - baseline))
    if ((create_delta >= 12)); then
      observed_create=1
      break
    fi
    sleep 0.1
  done
  if ((observed_create == 0)); then
    cat "${load_log}" >&2 || true
    fail_with_diagnostics "TURN UDP load did not create the expected upstream sockets"
  fi

  if ! wait "${load_pid}"; then
    cat "${load_log}" >&2 || true
    docker rm -f "${load_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "TURN UDP load client failed"
  fi
  docker rm -f "${load_container}" >/dev/null 2>&1 || true

  after_expire="${after_create}"
  for _ in $(seq 1 50); do
    after_expire="$(proxy_socket_fd_count)"
    assert_socket_fd_count "${after_expire}" "idle expiration"
    expire_delta=$((after_expire - baseline))
    if ((expire_delta <= 4)); then
      observed_expire=1
      break
    fi
    sleep 0.1
  done
  create_delta=$((after_create - baseline))
  expire_delta=$((after_expire - baseline))
  echo "TURN UDP socket fd counts: baseline=${baseline} after_create=${after_create} after_expire=${after_expire} create_delta=${create_delta} expire_delta=${expire_delta}"
  if ((observed_expire == 0)); then
    fail_with_diagnostics "expired TURN UDP sessions still retained upstream sockets"
  fi

  assert_udp_round_trip
}

wait_for_udp_turn_echo() {
  for _ in $(seq 1 50); do
    if docker exec "${http_container}" python -c '
import socket

payload = b"ready"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.2)
sock.sendto(payload, ("mock-turn-udp", 3478))
data, _ = sock.recvfrom(65535)
if data != payload:
    raise RuntimeError(f"unexpected TURN UDP readiness response: {data!r}")
' >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done
  fail_with_diagnostics "TURN UDP upstream did not become ready"
}

proxy_socket_fd_count() {
  docker exec "${proxy_container}" sh -c 'count=0; for fd in /proc/1/fd/*; do target="$(readlink "$fd" 2>/dev/null || true)"; case "$target" in socket:*) count=$((count + 1));; esac; done; printf "%s" "$count"'
}

assert_socket_fd_count() {
  local count="$1" phase="$2"
  if [[ ! "${count}" =~ ^[0-9]+$ ]]; then
    fail_with_diagnostics "TURN UDP socket fd count was nonnumeric during ${phase}"
  fi
}

assert_udp_round_trip() {
  local client_container="oxibelt-turn-udp-roundtrip-${run_id}-${RANDOM}"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import socket

# A zero-attribute STUN Binding request exercises the UDP session path without
# being rejected as malformed TURN ChannelData.
payload = bytes.fromhex("000100002112a442") + b"roundtrip-01"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(payload, ("proxy", 3478))
data, _ = sock.recvfrom(65535)
if data != payload:
    raise RuntimeError(f"unexpected TURN UDP echo: {data!r}")
' >/dev/null
  if ! docker start -a "${client_container}"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "TURN UDP round trip failed"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
}

start_udp_session_load() {
  local count="$1"
  local -n container_ref="$2" pid_ref="$3" log_ref="$4"

  container_ref="oxibelt-turn-udp-load-${run_id}-${RANDOM}"
  log_ref="${work_dir}/${container_ref}.log"
  docker create \
    --name "${container_ref}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import socket
import sys
import time

count = int(sys.argv[1])
stun_header = bytes.fromhex("000100002112a442")
sockets = []
for _ in range(count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sockets.append(sock)

deadline = time.monotonic() + 3
while time.monotonic() < deadline:
    for index, sock in enumerate(sockets):
        transaction_id = index.to_bytes(12, byteorder="big")
        sock.sendto(stun_header + transaction_id, ("proxy", 3478))
    time.sleep(0.1)
' "${count}" >/dev/null
  docker start -a "${container_ref}" >"${log_ref}" 2>&1 &
  pid_ref="$!"
}
