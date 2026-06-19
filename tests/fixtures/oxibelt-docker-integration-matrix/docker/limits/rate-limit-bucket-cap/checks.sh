
run_case_checks() {
  local first second repeated
  first="$(client_request_with_headers "example.test" "/app/rate-a" 200 "GET" "" "X-Api-Token: first-token")"
  assert_body_jq "${first}" '.path == "/origin/app/rate-a"'

  second="$(client_request_with_headers "example.test" "/app/rate-b" 429 "GET" "" "X-Api-Token: second-token")"
  assert_response_jq "${second}" '.body == "rate limit exceeded"'

  repeated="$(client_request_with_headers "example.test" "/app/rate-a" 429 "GET" "" "X-Api-Token: first-token")"
  assert_response_jq "${repeated}" '.body == "rate limit exceeded"'
}
