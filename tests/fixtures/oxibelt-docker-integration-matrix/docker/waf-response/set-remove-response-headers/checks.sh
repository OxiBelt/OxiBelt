
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/response-headers" 200)"
  assert_response_jq "${response}" '.headers["x-waf-response"] == "set" and .headers["x-upstream-marker"] == null'
}
