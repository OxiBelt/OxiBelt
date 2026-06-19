
run_case_checks() {
  local response
  response="$(split_body_client_request "example.test" "/app/stream" 403 "POST" "prefix split-secret suffix" 11 100 "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "streaming scan matched"'
}
