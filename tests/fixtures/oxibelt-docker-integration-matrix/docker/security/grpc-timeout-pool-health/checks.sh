
run_case_checks() {
  local first_timeout second_timeout recovered
  first_timeout="$(client_request_with_headers "grpc-pool.example.test" "/matrix.Security/Unary?header_delay_ms=100" 200 "POST" "" "Content-Type: application/grpc" "Grpc-Timeout: 0n")"
  assert_response_jq "${first_timeout}" '.headers["grpc-status"] == "4"'

  second_timeout="$(client_request_with_headers "grpc-pool.example.test" "/matrix.Security/Unary?header_delay_ms=100" 200 "POST" "" "Content-Type: application/grpc" "Grpc-Timeout: 0n")"
  assert_response_jq "${second_timeout}" '.headers["grpc-status"] == "4"'

  recovered="$(client_request "grpc-pool.example.test" "/after-timeout" 200)"
  assert_body_jq "${recovered}" '(.upstream == "http-upstream" or .upstream == "alt-upstream")
    and (.path == "/origin/after-timeout" or .path == "/alt/after-timeout")'
}
