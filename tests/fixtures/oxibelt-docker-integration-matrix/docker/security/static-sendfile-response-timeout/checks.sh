
run_case_checks() {
  local slow_client response

  response="$(plain_client_request "static-timeout.example.test" "/static/ok.txt" 200)"
  assert_response_jq "${response}" '.body == "static ok\n"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu '
    dd if=/dev/zero of=/etc/oxibelt/config/public/large.bin bs=1 count=0 seek=536870912 >/dev/null 2>&1
  '

  slow_client="$(start_unread_static_sendfile_client)"
  sleep 2
  probe_plain_static_ok_once
  docker rm -f "${slow_client}" >/dev/null 2>&1 || true
}

start_unread_static_sendfile_client() {
  local client_container
  client_container="$(unique_docker_container_name "oxibelt-static-sendfile-slow-client")"

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -u -c '
import socket
import time

sock = socket.create_connection(("proxy", 8080), timeout=5)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
sock.sendall(
    b"GET /static/large.bin HTTP/1.1\r\n"
    b"Host: static-timeout.example.test\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
print("slow static request sent", flush=True)
time.sleep(45)
sock.close()
' >/dev/null
  docker start "${client_container}" >/dev/null

  for _attempt in $(seq 1 50); do
    if docker logs "${client_container}" 2>&1 | grep -F "slow static request sent" >/dev/null; then
      printf '%s' "${client_container}"
      return 0
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "${client_container}" 2>/dev/null || echo false)" != "true" ]]; then
      docker logs "${client_container}" >&2 || true
      fail_with_diagnostics "slow static sendfile client exited before sending the request"
    fi
    sleep 0.1
  done

  docker logs "${client_container}" >&2 || true
  fail_with_diagnostics "slow static sendfile client did not send its request"
}

probe_plain_static_ok_once() {
  local client_container output
  client_container="$(unique_docker_container_name "oxibelt-static-sendfile-probe")"

  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import http.client

connection = http.client.HTTPConnection("proxy", 8080, timeout=5)
try:
    connection.request(
        "GET",
        "/static/ok.txt",
        headers={"Host": "static-timeout.example.test", "Connection": "close"},
    )
    response = connection.getresponse()
    body = response.read()
    if response.status != 200:
        raise RuntimeError(f"expected 200, got {response.status}: {body!r}")
    if body != b"static ok\n":
        raise RuntimeError(f"unexpected response body: {body!r}")
finally:
    connection.close()

print("second static request succeeded")
' >/dev/null

  if ! output="$(docker start -a "${client_container}" 2>&1)"; then
    echo "${output}" >&2
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "second static request failed while slow sendfile client was still open"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  if ! grep -F "second static request succeeded" <<<"${output}" >/dev/null; then
    echo "${output}" >&2
    fail_with_diagnostics "second static request assertion did not run"
  fi
}
