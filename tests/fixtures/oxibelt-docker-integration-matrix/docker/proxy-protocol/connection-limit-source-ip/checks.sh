
run_case_checks() {
  local same other
  start_holding_client_request_with_headers \
    "proxy" 8443 "https" "PROXY TCP4 203.0.113.30 192.0.2.10 45678 443" \
    "example.test" "/app/hold-proxy?body_delay_ms=3000" 200 4000

  if same="$(probe_proxy_protocol_client_request "PROXY TCP4 203.0.113.30 192.0.2.10 45679 443" "example.test" "/app/same-client" 2>/dev/null)"; then
    echo "${same}" >&2
    fail_with_diagnostics "same PROXY source IP unexpectedly reached the proxy while the first connection was held"
  fi

  other="$(proxy_protocol_client_request "PROXY TCP4 203.0.113.31 192.0.2.10 45680 443" "example.test" "/app/other-client" 200)"
  assert_body_jq "${other}" '.path == "/origin/app/other-client"'

  wait_holding_client
}
