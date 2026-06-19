
run_case_checks() {
  local response admin compat metrics
  response="$(client_request "example.test" "/app/monitor?q=UNION%20SELECT" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/monitor?q=UNION%20SELECT"'

  response="$(client_request "example.test" "/app/leak?content_type=text/plain&body=secret-leak" 200)"
  assert_response_jq "${response}" '.body == "secret-leak"'

  admin="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/waf/rule-hits" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${admin}" '([.rules[] | select(.scope == "crs" and .phase == "request" and .id == "942100" and .effective_mode == "monitor" and .hits == 1 and .latest_inbound_anomaly_score == 5)] | length) == 1'
  assert_body_jq "${admin}" '([.rules[] | select(.scope == "crs" and .phase == "response" and .id == "951100" and .effective_mode == "monitor" and .hits == 1 and .latest_outbound_anomaly_score == 4)] | length) == 1'

  compat="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/waf/crs/compatibility" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_body_jq "${compat}" '([.release_lines[] | select(.name == "current" and .version == "v4.25.0")] | length) == 1'
  assert_body_jq "${compat}" '.supported.directives | index("SecRule") != null'
  assert_body_jq "${compat}" '.accepted_but_ignored.directives | index("SecRuleRemoveById") != null'
  assert_body_jq "${compat}" '.known_unsupported | any(contains("WebTransport"))'

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_waf_rule_hits_total") | not'
  assert_response_jq "${metrics}" '.body | contains("942100") | not'
  assert_response_jq "${metrics}" '.body | contains("951100") | not'
}
