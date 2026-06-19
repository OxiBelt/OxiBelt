
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/h3-enabled" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/h3-enabled"'
}
      