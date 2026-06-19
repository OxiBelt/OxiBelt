
run_case_checks() {
  local timed_out allowed
  timed_out="$(client_request "slow-auth.example.test" "/app/protected" 503)"
  assert_response_jq "${timed_out}" '.body == "external authorization failed"'

  allowed="$(client_request "quick-auth.example.test" "/app/protected" 200)"
  assert_body_jq "${allowed}" '.upstream == "http-upstream" and .path == "/origin/app/protected"'
}
