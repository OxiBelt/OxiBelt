
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/h1" 200)"
  assert_body_jq "${response}" '.request_version == "HTTP/1.1"'
}
