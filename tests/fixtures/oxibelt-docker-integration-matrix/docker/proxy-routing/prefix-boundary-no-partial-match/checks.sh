
run_case_checks() {
  local matched partial
  matched="$(client_request "example.test" "/app/ok" 200)"
  assert_body_jq "${matched}" '.upstream == "http-upstream" and .path == "/origin/app/ok"'

  partial="$(client_request "example.test" "/application" 404)"
  assert_response_jq "${partial}" '.body == "no matching route"'
}
