
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/h1h2" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/h1h2"'
}
