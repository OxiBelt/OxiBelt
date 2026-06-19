
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/reuseport-workers" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/reuseport-workers"'
}
      