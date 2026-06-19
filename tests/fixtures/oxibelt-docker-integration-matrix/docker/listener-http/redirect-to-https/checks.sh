
run_case_checks() {
  local response
  response="$(plain_client_request "example.test" "/app/redirect?x=1" 308)"
  assert_response_jq "${response}" '.headers.location == "https://example.test/app/redirect?x=1"'
}
