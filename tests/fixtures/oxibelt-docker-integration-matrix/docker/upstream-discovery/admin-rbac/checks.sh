
upstream_pool_operator_etag() {
  local status
  status="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/status" 200 "GET" "" "Authorization: Bearer matrix-upstream-token")"
  jq -r '.body | fromjson | .etag' <<<"${status}"
}

run_case_checks() {
  local response
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_response_jq "${response}" '.body | fromjson | length == 1'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/status" 403 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_response_jq "${response}" '(.body | fromjson) as $body | $body.error.code == "permission_denied" and $body.error.details.action == "upstream-pool:GetStatus" and $body.error.details.resource == "oxibelt:oxibelt:upstream-pool:status/current"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/primary" 403 "PATCH" '{"state":"down"}' "Authorization: Bearer matrix-viewer-token")"
  assert_response_jq "${response}" '(.body | fromjson) as $body | $body.error.code == "permission_denied" and $body.error.message == "forbidden" and $body.error.details.action == "upstream-pool:UpdateServer"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool/servers/primary" 200 "PATCH" '{"state":"down"}' "Authorization: Bearer matrix-upstream-token" "If-Match: $(upstream_pool_operator_etag)")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools" 401 "GET" "" "Authorization: Bearer wrong-token")"
  assert_response_jq "${response}" '(.body | fromjson) as $body | $body.error.code == "unauthorized" and $body.error.message == "unauthorized"'
}
