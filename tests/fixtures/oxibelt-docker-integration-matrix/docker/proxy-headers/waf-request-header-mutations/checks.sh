
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/mutate" 200 "GET" "" "X-Remove-Me: present")"
  assert_body_jq "${response}" '.headers["x-waf-request"] == "set" and .headers["x-remove-me"] == null'
}
