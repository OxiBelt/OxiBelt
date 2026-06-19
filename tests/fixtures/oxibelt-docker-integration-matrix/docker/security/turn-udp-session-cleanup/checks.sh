
run_case_checks() {
  local baseline after_create after_expire create_delta expire_delta

  start_udp_turn_echo
  sleep 1

  baseline="$(proxy_socket_fd_count)"
  assert_udp_round_trip
  send_udp_packets_from_unique_ports 32 "session-load"
  sleep 1
  after_create="$(proxy_socket_fd_count)"
  create_delta=$((after_create - baseline))
  if (( create_delta < 12 )); then
    echo "socket fd counts: baseline=${baseline} after_create=${after_create}" >&2
    fail_with_diagnostics "TURN UDP load did not create the expected upstream sockets"
  fi

  sleep 1
  send_udp_packets_from_unique_ports 1 "expiration-trigger"
  sleep 1
  after_expire="$(proxy_socket_fd_count)"
  expire_delta=$((after_expire - baseline))
  echo "TURN UDP socket fd counts: baseline=${baseline} after_create=${after_create} after_expire=${after_expire} create_delta=${create_delta} expire_delta=${expire_delta}"
  if (( expire_delta > 4 )); then
    fail_with_diagnostics "expired TURN UDP sessions still retained upstream sockets"
  fi

  assert_udp_round_trip
}

start_udp_turn_echo() {
  docker run -d \
    --name "oxibelt-turn-upstream-${run_id}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --network-alias mock-turn \
    --entrypoint python \
    "${mock_image}" \
    -c '
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 3478))
while True:
    data, addr = sock.recvfrom(65535)
    sock.sendto(data, addr)
' >/dev/null
}

proxy_socket_fd_count() {
  docker exec "${proxy_container}" sh -c 'count=0; for fd in /proc/1/fd/*; do target="$(readlink "$fd" 2>/dev/null || true)"; case "$target" in socket:*) count=$((count + 1));; esac; done; printf "%s" "$count"'
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

payload = b"roundtrip"
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

send_udp_packets_from_unique_ports() {
  local count="$1"
  local payload="$2"
  local client_container="oxibelt-turn-udp-load-${run_id}-${RANDOM}"

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import socket
import sys
import time

count = int(sys.argv[1])
payload = sys.argv[2].encode("utf-8")
sockets = []
for index in range(count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sockets.append(sock)
    sock.sendto(payload + b":" + str(index).encode("ascii"), ("proxy", 3478))
time.sleep(0.2)
for sock in sockets:
    sock.close()
' "${count}" "${payload}" >/dev/null
  if ! docker start -a "${client_container}"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "TURN UDP load client failed"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
}
