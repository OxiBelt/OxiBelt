
run_case_checks() {
  local response
  response="$(proxy_protocol_client_request "PROXY TCP4 203.0.113.10 192.0.2.10 45678 443" "example.test" "/app/proxy-protocol" 409)"
  assert_response_jq "${response}" '.body == "proxy protocol source blocked"'
}
