
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/proxy-egress" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  assert_body_jq "${response}" '.proxy_protocol_line | startswith("PROXY TCP4 ")'
}
