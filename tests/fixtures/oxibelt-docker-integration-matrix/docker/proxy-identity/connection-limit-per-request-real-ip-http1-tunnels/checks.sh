
run_case_checks() {
  local same after

  start_holding_upgrade_client_request_with_headers \
    "example.test" "/upgrade-held" "matrix-upgrade" "held-upgrade" 101 2500 \
    "X-Forwarded-For: 203.0.113.30"

  same="$(upgrade_client_request_with_headers "example.test" "/upgrade-same" "matrix-upgrade" "blocked-upgrade" 429 "X-Forwarded-For: 203.0.113.30")"
  assert_response_jq "${same}" '.body == "connection limit exceeded"'

  wait_holding_client

  after="$(upgrade_client_request_with_headers "example.test" "/upgrade-after" "matrix-upgrade" "after-upgrade" 101 "X-Forwarded-For: 203.0.113.30")"
  assert_response_jq "${after}" '.body == "upgraded:after-upgrade"'

  start_holding_connect_tunnel_request_with_headers \
    "example.test" "/origin/connect-held?case=held" 200 2500 \
    "X-Forwarded-For: 203.0.113.31"

  same="$(connect_tunnel_request_with_headers "example.test" "/origin/connect-same?case=same" 429 "X-Forwarded-For: 203.0.113.31")"
  assert_response_jq "${same}" '.body == "connection limit exceeded"'

  wait_holding_client

  after="$(connect_tunnel_request_with_headers "example.test" "/origin/connect-after?case=after" 200 "X-Forwarded-For: 203.0.113.31")"
  assert_response_jq "${after}" '.body | fromjson | .path == "/origin/connect-after?case=after"'
}
