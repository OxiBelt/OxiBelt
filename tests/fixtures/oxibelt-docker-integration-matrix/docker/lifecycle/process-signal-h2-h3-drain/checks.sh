signal_drain_gate_request() {
  local method="$1"
  local path="$2"

  docker exec "${http_container}" python /opt/mock_upstream/client.py \
    --target-host 127.0.0.1 \
    --scheme http \
    --port 18080 \
    --host mock-http \
    --method "${method}" \
    --path "${path}" \
    --body "" \
    --dump-response-json \
    --expect-status 200 \
    --timeout 2
}

run_case_checks() {
  local gate_id="shutdown-drain"
  local gate_status=""
  local proxy_logs=""
  local response=""
  local exit_code=""
  local proxy_running="true"
  local index=""
  local client_output=""
  local -a drain_client_containers=()
  local -a drain_client_logs=()
  local -a drain_client_pids=()
  local -a drain_client_protocols=()
  local -a drain_client_bodies=()

  gate_status="$(plain_client_request_with_headers_to_target \
    "mock-http" 18080 "mock-http" "/__fault/gates/${gate_id}" 200 "GET" "")"
  assert_response_jq \
    "${gate_status}" \
    ".body | fromjson | .id == \"${gate_id}\" and .waiting == 0 and .released == false"
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/ready" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "ready"'

  for index in 1 2 3 4; do
    start_signal_drain_probe \
      "h2" \
      "${index}" \
      "${gate_id}" \
      drain_client_containers \
      drain_client_logs \
      drain_client_pids \
      drain_client_protocols \
      drain_client_bodies
    start_signal_drain_probe \
      "h3" \
      "${index}" \
      "${gate_id}" \
      drain_client_containers \
      drain_client_logs \
      drain_client_pids \
      drain_client_protocols \
      drain_client_bodies
  done

  for _attempt in $(seq 1 100); do
    gate_status="$(signal_drain_gate_request GET "/__fault/gates/${gate_id}")"
    if jq -e '.body | fromjson | .waiting == 8 and .released == false' \
      <<<"${gate_status}" >/dev/null; then
      break
    fi
    sleep 0.1
  done
  if ! jq -e '.body | fromjson | .waiting == 8 and .released == false' \
    <<<"${gate_status}" >/dev/null; then
    echo "${gate_status}" >&2
    fail_with_diagnostics "timed out waiting for all HTTP/2 and HTTP/3 requests to reach the upstream gate"
  fi

  docker kill --signal USR1 "${proxy_container}" >/dev/null
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/ready" 503 "GET" "")"
  assert_response_jq "${response}" '.body == "draining"'
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/live" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "live"'

  docker kill --signal TERM "${proxy_container}" >/dev/null
  response="$(signal_drain_gate_request POST "/__fault/gates/${gate_id}/release")"
  assert_body_jq "${response}" ".id == \"${gate_id}\" and .released == true"

  for index in "${!drain_client_pids[@]}"; do
    if ! wait "${drain_client_pids[${index}]}"; then
      cat "${drain_client_logs[${index}]}" >&2 || true
      fail_with_diagnostics "${drain_client_protocols[${index}]} drain probe failed"
    fi
    client_output="$(cat "${drain_client_logs[${index}]}")"
    assert_response_jq \
      "${client_output}" \
      ".negotiated_protocol == \"${drain_client_protocols[${index}]}\" and .status == 200 and .body == \"${drain_client_bodies[${index}]}\""
    docker rm -f "${drain_client_containers[${index}]}" >/dev/null 2>&1 || true
  done

  for _attempt in $(seq 1 150); do
    proxy_running="$(docker inspect -f '{{.State.Running}}' "${proxy_container}" 2>/dev/null || echo false)"
    if [[ "${proxy_running}" == "false" ]]; then
      break
    fi
    sleep 0.1
  done
  if [[ "${proxy_running}" != "false" ]]; then
    fail_with_diagnostics "proxy did not exit within the graceful process-shutdown deadline"
  fi
  exit_code="$(docker inspect -f '{{.State.ExitCode}}' "${proxy_container}")"
  if [[ "${exit_code}" != "0" ]]; then
    fail_with_diagnostics "proxy exited with status ${exit_code} after graceful process shutdown"
  fi
  proxy_logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  if grep -E 'panicked at|thread .* panicked' <<<"${proxy_logs}" >/dev/null; then
    echo "${proxy_logs}" >&2
    fail_with_diagnostics "proxy logged a panic during graceful process shutdown"
  fi

  docker start "${proxy_container}" >/dev/null
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/ready" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "ready"'
  response="$(protocol_probe_client "h2" "example.test" "/fresh-h2?body=fresh-h2" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h2" and .body == "fresh-h2"'
  response="$(protocol_probe_client "h3" "example.test" "/fresh-h3?body=fresh-h3" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3" and .body == "fresh-h3"'
}

start_signal_drain_probe() {
  local protocol="$1"
  local request_index="$2"
  local gate_id="$3"
  local -n containers_ref="$4"
  local -n logs_ref="$5"
  local -n pids_ref="$6"
  local -n protocols_ref="$7"
  local -n bodies_ref="$8"
  local client_container=""
  local client_log=""
  local body="${protocol}-${request_index}"

  client_container="$(unique_docker_container_name "oxibelt-signal-drain-${protocol}")"
  client_log="${logs_dir}/${client_container}.log"
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
    --authority example.test \
    --path "/drain-${body}?gate=${gate_id}&gate_timeout_ms=30000&body=${body}" \
    --ca-cert /tmp/probe-ca.pem \
    --expect-status 200 >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/probe-ca.pem"
  docker start -a "${client_container}" >"${client_log}" 2>&1 &

  containers_ref+=("${client_container}")
  logs_ref+=("${client_log}")
  pids_ref+=("$!")
  protocols_ref+=("${protocol}")
  bodies_ref+=("${body}")
}
