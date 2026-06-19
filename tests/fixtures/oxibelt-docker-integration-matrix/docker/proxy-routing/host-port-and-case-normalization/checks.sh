
run_case_checks() {
  local response
  response="$(client_request "API.EXAMPLE.TEST:443" "/case/host-port" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/case/host-port"'
}
