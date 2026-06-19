
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/monitor" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/monitor"'
}
