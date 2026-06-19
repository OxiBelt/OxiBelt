
run_case_checks() {
  local response
  response="$(client_request "example.test" "/api/users" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/api/users"'
}
