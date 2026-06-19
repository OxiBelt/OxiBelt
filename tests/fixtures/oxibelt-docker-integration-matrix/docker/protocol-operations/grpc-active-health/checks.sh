
run_case_checks() {
  sleep 2
  local response
  response="$(client_request "example.test" "/app/grpc-health" 200)"
  assert_body_jq "${response}" '.upstream == "h2c-upstream" and .request_version == "HTTP/2.0"'
}
