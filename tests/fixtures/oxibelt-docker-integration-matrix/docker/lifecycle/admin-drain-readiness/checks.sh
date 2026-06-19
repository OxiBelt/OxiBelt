
run_case_checks() {
  local response held_output

  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/ready" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "ready"'
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/live" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "live"'
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/lifecycle" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${response}" '.draining == false and .reason == "ready"'

  start_holding_client_request_with_headers \
    "proxy" \
    8443 \
    "https" \
    "" \
    "example.test" \
    "/app/held?body=held-ok&body_delay_ms=3500" \
    200 \
    0

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/lifecycle/drain" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_body_jq "${response}" '.ok == true'
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/lifecycle" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${response}" '.draining == true and .reason == "admin"'
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/ready" 503 "GET" "")"
  assert_response_jq "${response}" '.body == "draining"'
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/live" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "live"'
  response="$(client_request_with_headers "example.test" "/app/rejected" 503 "GET" "")"
  assert_response_jq "${response}" '.body == "draining" and (.headers.connection | ascii_downcase) == "close"'

  wait_holding_client
  held_output="$(cat "${HOLDING_CLIENT_LOG}")"
  assert_response_jq "${held_output}" '.status == 200 and .body == "held-ok"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/lifecycle/undrain" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_body_jq "${response}" '.ok == true'
  response="$(plain_client_request_with_headers_on_port 9091 "proxy" "/ready" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "ready"'
  response="$(client_request_with_headers "example.test" "/app/restored?body=restored" 200 "GET" "")"
  assert_response_jq "${response}" '.body == "restored"'
}
