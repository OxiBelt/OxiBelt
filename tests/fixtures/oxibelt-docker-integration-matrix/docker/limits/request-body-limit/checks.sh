
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/body-limit" 413 "POST" "too-large" "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "request body is too large"'
}
