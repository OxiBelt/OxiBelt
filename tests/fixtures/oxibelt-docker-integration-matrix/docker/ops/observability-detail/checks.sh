
run_case_checks() {
  local response metrics admin incoming_traceparent
  incoming_traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

  response="$(client_request_with_headers "example.test" "/app/observability-seed" 200 "GET" "" "traceparent: ${incoming_traceparent}")"
  assert_body_jq "${response}" '.path == "/origin/app/observability-seed"'
  assert_body_jq "${response}" '.headers.traceparent | test("^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$")'
  assert_body_jq "${response}" ".headers.traceparent != \"${incoming_traceparent}\""

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_http_requests_total{")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_http_request_duration_ms_bucket{")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_upstream_requests_total{")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_upstream_request_duration_ms_bucket{")'
  assert_response_jq "${metrics}" '.body | contains("route=\"main-route\"")'
  assert_response_jq "${metrics}" '.body | contains("upstream=\"http-upstream\"")'
  assert_response_jq "${metrics}" '.body | contains("method=\"GET\"")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"h1\"")'
  assert_response_jq "${metrics}" '.body | contains("status=\"200\"")'
  assert_response_jq "${metrics}" '.body | contains("status_class=\"2xx\"")'
  assert_response_jq "${metrics}" '.body | contains("upstream_protocol=\"http\"")'
  assert_response_jq "${metrics}" '.body | contains("outcome=\"success\"")'
  assert_response_jq "${metrics}" '.body | contains("rule_name") | not'
  assert_response_jq "${metrics}" '.body | contains("rule_id") | not'
  assert_response_jq "${metrics}" '.body | contains("obs-cost-rule") | not'
  assert_response_jq "${metrics}" '.body | contains("obs-cost-tag") | not'

  admin="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/waf/rule-costs" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${admin}" '([.rules[] | select(.scope == "global" and .route == null and .phase == "request" and .name == "obs-cost-rule" and .id == "obs-cost-rule" and (.tags | index("obs-cost-tag") != null) and .effective_mode == "monitor" and .evaluations >= 1 and .total_duration_ns >= .average_duration_ns)] | length) == 1'
}
