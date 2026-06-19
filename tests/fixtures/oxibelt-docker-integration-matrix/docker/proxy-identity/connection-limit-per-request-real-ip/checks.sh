
run_case_checks() {
  local same after
  start_holding_client_request_with_headers \
    "proxy" 8443 "https" "" \
    "example.test" "/app/hold-per-request?body_delay_ms=3000" 200 4000 \
    "X-Forwarded-For: 203.0.113.20"

  same="$(client_request_with_headers "example.test" "/app/same-client" 429 "GET" "" "X-Forwarded-For: 203.0.113.20")"
  assert_response_jq "${same}" '.body == "connection limit exceeded"'

  wait_holding_client

  after="$(client_request_with_headers "example.test" "/app/after-release" 200 "GET" "" "X-Forwarded-For: 203.0.113.20")"
  assert_body_jq "${after}" '.path == "/origin/app/after-release"'
}
