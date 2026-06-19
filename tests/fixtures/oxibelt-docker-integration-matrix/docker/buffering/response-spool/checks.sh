
run_case_checks() {
  assert_no_buffer_temp_files() {
    local label="$1"
    local temp_count
    temp_count="$(docker exec "${proxy_container}" sh -c 'find /var/cache/oxibelt -maxdepth 1 -type f -name "oxibelt-buffer-*" | wc -l' | tr -d "[:space:]")"
    if [[ "${temp_count}" != "0" ]]; then
      docker exec "${proxy_container}" sh -c 'ls -la /var/cache/oxibelt' >&2 || true
      fail_with_diagnostics "expected ${label} buffering temp files to be removed"
    fi
  }

  local oversized_body response
  start_holding_client_request_with_headers "proxy" 8443 "https" "" "example.test" "/app/download?body=spooled-response-body-0123456789" 200 3000
  wait_holding_client
  response="$(cat "${HOLDING_CLIENT_LOG}")"
  assert_response_jq "${response}" '.body == "spooled-response-body-0123456789"'
  assert_no_buffer_temp_files "successful response"

  printf -v oversized_body '%*s' 135 ''
  oversized_body="${oversized_body// /x}"
  response="$(client_request "example.test" "/app/download?body=${oversized_body}&body_split_at=5&body_split_delay_ms=100" 502)"
  assert_response_jq "${response}" '.body == "upstream response body is too large"'
  assert_no_buffer_temp_files "oversized response"
}
