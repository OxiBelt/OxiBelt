
run_case_checks() {
  local response
  response="$(plain_client_request_on_port 15432 "stream.example.test" "/stream/direct?case=tcp" 200)"
  assert_response_jq "${response}" '.body | fromjson | .upstream == "http-upstream"'
  assert_response_jq "${response}" '.body | fromjson | .path == "/stream/direct?case=tcp"'
}
