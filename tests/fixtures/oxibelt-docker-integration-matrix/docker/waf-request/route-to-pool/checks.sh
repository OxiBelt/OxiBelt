
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/pool-canary" 200 "GET" "" "X-Use-Pool: yes")"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/app/pool-canary"'
}
