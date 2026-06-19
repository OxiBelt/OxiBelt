
run_case_checks() {
  local request response
  request="$(client_request_with_headers "example.test" "/app/udf-request" 403 "POST" "prefix blocked suffix" "Content-Type: text/plain")"
  assert_response_jq "${request}" '.body == "udf request body blocked"'

  response="$(client_request "example.test" "/app/udf-response?body=prefix%20leak%20suffix" 451)"
  assert_response_jq "${response}" '.body == "udf response body blocked"'
}
