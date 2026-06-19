
run_case_checks() {
  local response
  response="$(client_request "example.test" "/status/503" 502)"
  assert_response_jq "${response}" '.body == "matrix replacement"'
}
