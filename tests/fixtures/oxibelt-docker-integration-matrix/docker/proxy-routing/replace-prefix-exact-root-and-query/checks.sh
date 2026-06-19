
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app?x=1&y=two" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/edge?x=1&y=two"'
}
