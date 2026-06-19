
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/blocked" 403)"
  assert_response_jq "${response}" '.body == "Blocked by matrix WAF"'
}
