
run_case_checks() {
  local success rejected
  success="$(protocol_probe_websocket_client "ws.example.test" "/ws/echo" 101 "probe-websocket")"
  assert_response_jq "${success}" '.status == 101 and .upgraded == true and .echoed_bytes == 15'

  rejected="$(protocol_probe_websocket_client "ws-disabled.example.test" "/ws/echo" 502 "blocked-websocket")"
  assert_response_jq "${rejected}" '.status == 502 and .upgraded == false'
}
