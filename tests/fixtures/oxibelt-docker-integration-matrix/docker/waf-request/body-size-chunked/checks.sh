
run_case_checks() {
  local response
  response="$(chunked_body_client_request "example.test" "/app/upload" 413 "POST" "123456789" "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "request body too large"'
}
