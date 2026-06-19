
run_case_checks() {
  local response
  response="$(slow_body_client_request "example.test" "/app/slow-upload" 408 "POST" "slow-body" 1200 "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "request body timed out"'
}
