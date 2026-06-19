
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/route-block" 409)"
  assert_response_jq "${response}" '.body == "route waf"'
}
