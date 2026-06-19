
start_static_fifo_request() {
  BLOCKING_STATIC_CLIENT_CONTAINER="$(unique_docker_container_name "oxibelt-static-openat2-blocking-client")"
  BLOCKING_STATIC_CLIENT_LOG="${logs_dir}/${BLOCKING_STATIC_CLIENT_CONTAINER}.log"
  docker create \
    --name "${BLOCKING_STATIC_CLIENT_CONTAINER}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c '
import http.client
import json
import socket
import ssl

context = ssl.create_default_context(cafile="/tmp/proxy-ca.pem")
context.minimum_version = ssl.TLSVersion.TLSv1_2
sock = socket.create_connection(("proxy", 8443), timeout=5)
try:
    sock = context.wrap_socket(sock, server_hostname="proxy")
    sock.sendall(
        b"GET /static/blocking.fifo HTTP/1.1\r\n"
        b"Host: static-blocking.example.test\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    print("static FIFO request sent", flush=True)
    sock.settimeout(15)
    response = http.client.HTTPResponse(sock, method="GET")
    response.begin()
    body = response.read().decode("utf-8", "replace")
    print(json.dumps({"status": response.status, "body": body}, sort_keys=True), flush=True)
    if response.status != 403 or body != "forbidden":
        raise SystemExit(f"unexpected static FIFO response {response.status}: {body!r}")
finally:
    sock.close()
' >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${BLOCKING_STATIC_CLIENT_CONTAINER}:/tmp/proxy-ca.pem"
  docker start -a "${BLOCKING_STATIC_CLIENT_CONTAINER}" >"${BLOCKING_STATIC_CLIENT_LOG}" 2>&1 &
  BLOCKING_STATIC_CLIENT_PID=$!
}

wait_for_static_fifo_request_sent() {
  local attempt state
  for attempt in $(seq 1 50); do
    if grep -F "static FIFO request sent" "${BLOCKING_STATIC_CLIENT_LOG}" >/dev/null 2>&1; then
      return 0
    fi
    state="$(docker inspect -f '{{.State.Status}}' "${BLOCKING_STATIC_CLIENT_CONTAINER}" 2>/dev/null || echo missing)"
    if [[ "${state}" == "exited" || "${state}" == "dead" || "${state}" == "missing" ]]; then
      cat "${BLOCKING_STATIC_CLIENT_LOG}" >&2 || true
      fail_with_diagnostics "blocking static FIFO request exited before sending"
    fi
    sleep 0.1
  done
  cat "${BLOCKING_STATIC_CLIENT_LOG}" >&2 || true
  fail_with_diagnostics "blocking static FIFO request was not sent"
}

short_timeout_upstream_request() {
  local client_container output status
  client_container="$(unique_docker_container_name "oxibelt-openat2-upstream-probe")"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --path "/app/openat2-worker?body=runtime-free" \
    --host "app-blocking.example.test" \
    --port 8443 \
    --ca-file /tmp/proxy-ca.pem \
    --dump-response-json \
    --expect-status 200 \
    --timeout 1 >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

  if output="$(docker_start_stdout_only "${client_container}")"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    printf '%s' "${output}"
    return 0
  fi
  status=$?
  append_container_stderr "${client_container}"
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  echo "${output}" >&2
  fail_with_diagnostics "unrelated upstream request timed out while static FIFO open was pending"
}

run_case_checks() {
  local response
  local fifo_writer_status=0

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu \
    'rm -f /etc/oxibelt/config/public/blocking.fifo && mkfifo /etc/oxibelt/config/public/blocking.fifo'

  start_static_fifo_request
  wait_for_static_fifo_request_sent
  sleep 1

  response="$(short_timeout_upstream_request)"
  assert_response_jq "${response}" '.body == "runtime-free"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu \
    'timeout 5 sh -c "printf x > /etc/oxibelt/config/public/blocking.fifo"' \
    || fifo_writer_status=$?
  if [[ "${fifo_writer_status}" != "0" && "${fifo_writer_status}" != "141" ]]; then
    fail_with_diagnostics "failed to unblock blocking static FIFO request"
  fi
  if ! wait "${BLOCKING_STATIC_CLIENT_PID}"; then
    cat "${BLOCKING_STATIC_CLIENT_LOG}" >&2 || true
    fail_with_diagnostics "blocking static FIFO request did not finish as forbidden"
  fi
  docker rm -f "${BLOCKING_STATIC_CLIENT_CONTAINER}" >/dev/null 2>&1 || true
}
