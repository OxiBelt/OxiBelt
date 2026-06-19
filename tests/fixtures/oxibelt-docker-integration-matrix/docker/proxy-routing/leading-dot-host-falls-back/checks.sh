
run_case_checks() {
  local valid leading_dot
  valid="$(client_request "api.example.test" "/app/valid-wildcard" 200)"
  assert_body_jq "${valid}" '.upstream == "http-upstream" and .path == "/origin/app/valid-wildcard"'

  leading_dot="$(client_request ".example.test" "/app/leading-dot" 200)"
  assert_body_jq "${leading_dot}" '.upstream == "alt-upstream" and .path == "/alt/app/leading-dot"'
}
