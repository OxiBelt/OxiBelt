
run_case_checks() {
  local response
  response="$(protocol_probe_zero_length_body_delay_request "example.test" "/app/zero-length-stall" 408 "POST" 1200)"
  assert_response_jq "${response}" '.body == "request body timed out"'
}
