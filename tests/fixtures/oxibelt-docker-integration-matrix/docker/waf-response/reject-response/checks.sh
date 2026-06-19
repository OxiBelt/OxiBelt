
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/sensitive" 451)"
  assert_response_jq "${response}" '.body == "response rejected"'
}
