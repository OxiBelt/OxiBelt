
wait_for_managed_mitigation() {
  local status=""
  local count=""
  for _attempt in $(seq 1 30); do
    status="$(postgres_query "SELECT status FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
    count="$(postgres_query "SELECT count FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
    if [[ "${status}" == "pending" && "${count}" == "2" ]]; then
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "expected managed mitigation row to reach pending/count=2, got status=${status:-<empty>} count=${count:-<empty>}"
}

run_case_checks() {
  local first second row_count status count target_ip custom_path metrics
  first="$(client_request_with_headers "example.test" "/app/mitigate?case=one" 200 "GET" "" "X-Mitigation-Target: 203.0.113.80" "User-Agent: mitigation-one")"
  assert_body_jq "${first}" '.path == "/origin/app/mitigate?case=one"'

  second="$(client_request_with_headers "example.test" "/app/mitigate?case=two" 200 "GET" "" "X-Mitigation-Target: 203.0.113.80" "User-Agent: mitigation-two")"
  assert_body_jq "${second}" '.path == "/origin/app/mitigate?case=two"'

  wait_for_managed_mitigation

  row_count="$(postgres_query "SELECT count(*) FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
  if [[ "${row_count}" != "1" ]]; then
    fail_with_diagnostics "expected one managed mitigation aggregate row, got ${row_count}"
  fi

  status="$(postgres_query "SELECT status FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
  count="$(postgres_query "SELECT count FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
  target_ip="$(postgres_query "SELECT host(target_ip) FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
  custom_path="$(postgres_query "SELECT record->'custom'->>'path' FROM oxibelt_mitigation_events WHERE namespace = 'matrix-mitigation' AND intent = 'rtbh' AND provider = 'matrix-isp' AND target = '203.0.113.80';")"
  if [[ "${status}" != "pending" || "${count}" != "2" || "${target_ip}" != "203.0.113.80" || "${custom_path}" != "/app/mitigate" ]]; then
    fail_with_diagnostics "unexpected managed mitigation row status=${status} count=${count} target_ip=${target_ip} custom_path=${custom_path}"
  fi

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_mitigation_queued_total")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_mitigation_write_errors_total 0")'
}
