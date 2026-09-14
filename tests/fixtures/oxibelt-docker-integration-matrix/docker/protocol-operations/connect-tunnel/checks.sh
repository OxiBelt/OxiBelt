
run_case_checks() {
  local response
  response="$(connect_tunnel_request "example.test" "/origin/connect-tunnel?case=connect" 200)"
  assert_response_jq "${response}" '.body | fromjson | .upstream == "http-upstream"'
  assert_response_jq "${response}" '.body | fromjson | .path == "/origin/connect-tunnel?case=connect"'

  rejected="$(connect_tunnel_optimistic_request "connect-failure.example.test" "/origin/should-not-dispatch?case=optimistic-connect" 502)"
  assert_response_jq "${rejected}" '.status == 502'
  assert_response_jq "${rejected}" '.headers.connection == "close"'
  assert_response_jq "${rejected}" '.body | contains("failed to establish CONNECT tunnel")'
}
