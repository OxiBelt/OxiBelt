
run_case_checks() {
  local response
  response="$(client_request "secure.example.test" "/secure/health" 200)"
  assert_body_jq "${response}" '.upstream == "https-upstream" and .scheme == "https" and .headers.host == "secure.example.test"'
}
