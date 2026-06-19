
upstream_pool_etag() {
  local status
  status="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/status" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  jq -r '.body | fromjson | .etag' <<<"${status}"
}

run_case_checks() {
  local response first second state
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/primary" 428 "PATCH" '{"state":"down"}' "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body | fromjson | .error.message | contains("If-Match is required")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/primary" 412 "PATCH" '{"state":"down"}' "Authorization: Bearer matrix-admin-token" "If-Match: \"oxibelt-upstream-pools-stale\"")"
  assert_response_jq "${response}" '.body | fromjson | .error.message | contains("If-Match does not match")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/primary" 200 "PATCH" '{"state":"down"}' "Authorization: Bearer matrix-admin-token" "If-Match: $(upstream_pool_etag)")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  first="$(client_request "example.test" "/app/admin-down-a" 200)"
  second="$(client_request "example.test" "/app/admin-down-b" 200)"
  assert_body_jq "${first}" '.upstream == "alt-upstream"'
  assert_body_jq "${second}" '.upstream == "alt-upstream"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/primary" 200 "PATCH" '{"state":"ready","weight":2}' "Authorization: Bearer matrix-admin-token" "If-Match: $(upstream_pool_etag)")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/alt" 200 "PATCH" '{"weight":1}' "Authorization: Bearer matrix-admin-token" "If-Match: $(upstream_pool_etag)")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${state}" '.body | fromjson | ([.servers[] | select(.id == "primary" and .state == "ready" and .weight == 2)] | length) == 1'
  assert_response_jq "${state}" '.body | fromjson | ([.servers[] | select(.id == "alt" and .state == "ready" and .weight == 1)] | length) == 1'

  response="$(client_request "example.test" "/app/admin-weight-route" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" or .upstream == "alt-upstream"'
}
