
run_case_checks() {
  local response metrics admin
  response="$(client_request "example.test" "/app/shadow" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/shadow"'

  response="$(client_request "example.test" "/app/block" 451)"
  assert_response_jq "${response}" '.body == "blocked by rule"'

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_requests_total")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_waf_rule_hits_total") | not'
  assert_response_jq "${metrics}" '.body | contains("rule_name") | not'
  assert_response_jq "${metrics}" '.body | contains("rule_id") | not'
  assert_response_jq "${metrics}" '.body | contains("shadow-path") | not'
  assert_response_jq "${metrics}" '.body | contains("block-path") | not'

  admin="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/waf/rule-hits" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${admin}" '([.rules[] | select(.scope == "global" and .route == null and .phase == "request" and .name == "shadow-path" and .id == "shadow-path" and .effective_mode == "monitor" and .hits == 1)] | length) == 1'
  assert_body_jq "${admin}" '([.rules[] | select(.scope == "global" and .route == null and .phase == "request" and .name == "block-path" and .id == "block-path" and .effective_mode == "enforcing" and .hits == 1)] | length) == 1'
}
