
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/scan" 451)"
  assert_response_jq "${response}" '.body == "response body scan matched"'
}
