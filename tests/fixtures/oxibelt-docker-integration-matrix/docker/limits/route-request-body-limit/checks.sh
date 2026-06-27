
run_case_checks() {
  local accepted rejected
  accepted="$(client_request_with_headers "example.test" "/upload/body" 200 "POST" "123456" "Content-Type: text/plain")"
  assert_body_jq "${accepted}" '.path == "/origin/upload/body" and .body == "123456"'

  rejected="$(client_request_with_headers "example.test" "/default/body" 413 "POST" "123456" "Content-Type: text/plain")"
  assert_response_jq "${rejected}" '.body == "request body is too large"'
}
