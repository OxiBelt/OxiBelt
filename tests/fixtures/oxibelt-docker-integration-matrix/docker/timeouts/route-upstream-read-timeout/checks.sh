
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/stalled-body?body_delay_ms=1200" 504)"
  assert_response_jq "${response}" '.body == "upstream response body timed out"'
}
