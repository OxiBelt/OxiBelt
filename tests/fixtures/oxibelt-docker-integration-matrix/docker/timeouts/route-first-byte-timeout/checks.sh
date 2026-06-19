
run_case_checks() {
  local short_response long_response
  short_response="$(client_request "example.test" "/short/delay?header_delay_ms=1200" 504)"
  assert_response_jq "${short_response}" '.body == "upstream request failed"'

  long_response="$(client_request "example.test" "/long/delay?header_delay_ms=1200" 200)"
  assert_body_jq "${long_response}" '.path == "/origin/app/delay?header_delay_ms=1200"'
}
