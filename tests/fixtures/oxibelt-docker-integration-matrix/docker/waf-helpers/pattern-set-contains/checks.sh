
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/pattern" 403 "GET" "" "User-Agent: MatrixBadBot/1.0")"
  assert_response_jq "${response}" '.body == "pattern set matched"'
}
