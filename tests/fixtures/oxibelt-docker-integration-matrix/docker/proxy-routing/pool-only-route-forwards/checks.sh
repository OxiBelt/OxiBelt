
run_case_checks() {
  local response
  response="$(client_request "example.test" "/pool/only" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/pool/only"'
}
