
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/old?debug=true" 308)"
  assert_response_jq "${response}" '.headers.location == "/new/old?debug=true"'
}
