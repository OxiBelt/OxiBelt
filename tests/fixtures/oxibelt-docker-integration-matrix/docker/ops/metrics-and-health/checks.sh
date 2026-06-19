
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/metrics-seed" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/metrics-seed"'

  response="$(plain_client_request_on_port 9091 "ops.test" "/ready" 200)"
  assert_response_jq "${response}" '.body == "ready"'

  response="$(plain_client_request_on_port 9091 "ops.test" "/live" 200)"
  assert_response_jq "${response}" '.body == "live"'

  response="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${response}" '.body | contains("oxibelt_requests_total")'
}
