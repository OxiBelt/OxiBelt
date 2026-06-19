
run_case_checks() {
  local response
  response="$(connect_tunnel_request "example.test" "/origin/connect-tunnel?case=connect" 200)"
  assert_response_jq "${response}" '.body | fromjson | .upstream == "http-upstream"'
  assert_response_jq "${response}" '.body | fromjson | .path == "/origin/connect-tunnel?case=connect"'
}
