
upstream_pool_etag() {
  local status
  status="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/status" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  jq -r '.body | fromjson | .etag' <<<"${status}"
}

run_case_checks() {
  local response state metrics
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/good" 200 "PATCH" '{"state":"down"}' "Authorization: Bearer matrix-admin-token" "If-Match: $(upstream_pool_etag)")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/good" 200 "PATCH" '{"state":"ready"}' "Authorization: Bearer matrix-admin-token" "If-Match: $(upstream_pool_etag)")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${state}" '.body | fromjson | ([.servers[] | select(.id == "good" and .slow_start_remaining_ms != null and .effective_weight_percent >= 10 and .effective_weight_percent < 100)] | length) == 1'

  response="$(client_request "example.test" "/app/outlier-failover" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream"'

  state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${state}" '.body | fromjson | ([.servers[] | select(.id == "bad" and .source == "static" and .health_reason == "outlier_ejected" and .ejection_count >= 1 and .ejected_until_ms != null)] | length) == 1'
  assert_response_jq "${state}" '.body | fromjson | ([.servers[] | select(.id == "good" and .last_health_check_ms != null and .health_reason == "passive_success")] | length) == 1'

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_upstream_pool_servers")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_upstream_pool_health_reports_total")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_upstream_pool_outlier_ejections_total")'
  assert_response_jq "${metrics}" '.body | contains("pool=\"app-pool\"")'
  assert_response_jq "${metrics}" '.body | contains("source=\"static\"")'
  assert_response_jq "${metrics}" '.body | contains("reason=\"outlier_ejected\"")'
  assert_response_jq "${metrics}" '.body | contains("mock-http") | not'
  assert_response_jq "${metrics}" '.body | contains("http://") | not'
}
