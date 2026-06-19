
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/upload" 415 "POST" "plain text body" "Content-Type: application/octet-stream")"
  assert_response_jq "${response}" '.body == "not png"'
}
