
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/expect" 200 "POST" "hello" "Expect: 100-continue")"
  assert_body_jq "${response}" '.body == "hello" and .headers.expect == null'

  response="$(client_request_with_headers "example.test" "/app/bad-expect" 417 "GET" "" "Expect: custom-token")"
  assert_response_jq "${response}" '.status == 417'

  response="$(client_request_with_headers "example.test" "/app/priority" 200 "GET" "" "Priority: u=1")"
  assert_body_jq "${response}" '.headers.priority == null'
}
