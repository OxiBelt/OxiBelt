
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/chunked-response?body=123456789&chunked_response=1&body_split_at=4" 451)"
  assert_response_jq "${response}" '.body == "response body too large"'
}
