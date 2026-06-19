
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/missing" 502)"
  assert_response_jq "${response}" '.body == "upstream synthetic error replaced"'
}
