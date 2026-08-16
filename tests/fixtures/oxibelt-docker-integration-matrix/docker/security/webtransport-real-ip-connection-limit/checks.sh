
real_ip_fault_gate_request() {
  local method="$1" path="$2"
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
  local gate_id="webtransport-real-ip-holder"
  local holder_log="${work_dir}/held-real-ip-request.json"
  local holder_pid=""
  local response blocked gate_status

  protocol_probe_client_with_headers \
    h3 \
    "example.test" \
    "/app/hold?gate=${gate_id}&gate_timeout_ms=30000&body=held" \
    200 \
    "GET" \
    "" \
    "X-Forwarded-For: 203.0.113.77" >"${holder_log}" &
  holder_pid="$!"

  for _ in $(seq 1 100); do
    gate_status="$(real_ip_fault_gate_request GET "/__fault/gates/${gate_id}")"
    if jq -e --arg id "${gate_id}" \
      '.body | fromjson | .id == $id and .waiting == 1 and .released == false' \
      <<<"${gate_status}" >/dev/null; then
      break
    fi
    sleep 0.1
  done
  if ! jq -e --arg id "${gate_id}" \
    '.body | fromjson | .id == $id and .waiting == 1 and .released == false' \
    <<<"${gate_status}" >/dev/null; then
    real_ip_fault_gate_request POST "/__fault/gates/${gate_id}/release" >/dev/null 2>&1 || true
    wait "${holder_pid}" >/dev/null 2>&1 || true
    cat "${holder_log}" >&2 || true
    fail_with_diagnostics "held Real-IP request did not reach the upstream gate"
  fi

  blocked="$(protocol_probe_client_with_headers \
    h3 \
    "example.test" \
    "/app/blocked-while-held" \
    429 \
    "GET" \
    "" \
    "X-Forwarded-For: 203.0.113.77")"
  assert_response_jq "${blocked}" '.status == 429'

  response="$(protocol_probe_webtransport_multiplex \
    "example.test" \
    "/wt/session" \
    1 \
    "429" \
    --header "X-Forwarded-For: 203.0.113.77")"
  assert_response_jq "${response}" '.statuses == [429]'

  gate_status="$(real_ip_fault_gate_request POST "/__fault/gates/${gate_id}/release")"
  assert_response_jq "${gate_status}" '.body | fromjson | .released == true'
  if ! wait "${holder_pid}"; then
    cat "${holder_log}" >&2 || true
    fail_with_diagnostics "held Real-IP request failed"
  fi

  response="$(protocol_probe_webtransport_multiplex \
    "example.test" \
    "/wt/session-after-release" \
    1 \
    "200" \
    --header "X-Forwarded-For: 203.0.113.77")"
  assert_response_jq "${response}" '.statuses == [200]'
}
