
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/external" 403)"
  assert_response_jq "${response}" '.body == "external rule"'
}
