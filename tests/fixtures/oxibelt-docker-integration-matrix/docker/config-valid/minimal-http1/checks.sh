
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/ping?case=minimal" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/ping?case=minimal"'
}
