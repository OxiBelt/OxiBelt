
run_case_checks() {
  local empty_response oversized_response
  empty_response="$(protocol_probe_client_with_headers "h3" "example.test" "/app/cl0-empty" 200 "GET" "")"
  assert_body_jq "${empty_response}" '.path == "/origin/app/cl0-empty" and .body == ""'

  oversized_response="$(protocol_probe_generated_body_request "h3" "example.test" "/app/cl0-too-large" "GET" 8 8 --omit-content-length --header "Content-Length: 0" --expect-status 413)"
  assert_response_jq "${oversized_response}" '.body == "request body is too large"'
}
