
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
  response="$(client_request_with_headers "example.test" "/app/upload" 200 "POST" "spooled-request-body" "Content-Type: text/plain")"
  assert_body_jq "${response}" '.body == "spooled-request-body"'
  assert_no_buffer_temp_files "successful request"

  printf -v oversized_body '%*s' 135 ''
  oversized_body="${oversized_body// /x}"
  response="$(split_body_client_request "example.test" "/app/upload" 413 "POST" "${oversized_body}" 5 100 "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "request body is too large"'
  assert_no_buffer_temp_files "oversized request"
}
