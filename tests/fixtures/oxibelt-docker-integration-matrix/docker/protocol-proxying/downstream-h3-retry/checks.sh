
run_case_checks() {
  local response
  response="$(protocol_probe_client "h3" "example.test" "/app/retry-enabled" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3"'
  assert_body_jq "${response}" '.path == "/origin/app/retry-enabled"'
}
