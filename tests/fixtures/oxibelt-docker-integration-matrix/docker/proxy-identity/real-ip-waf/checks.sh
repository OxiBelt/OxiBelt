
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/real-ip" 451 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_response_jq "${response}" '.body == "real ip blocked"'

  response="$(client_request "example.test" "/app/real-ip" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/real-ip"'
}
