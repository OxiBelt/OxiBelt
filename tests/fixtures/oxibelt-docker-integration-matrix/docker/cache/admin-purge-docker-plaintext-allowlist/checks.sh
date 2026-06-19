
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/admin-plain-purge?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/admin-plain-purge?cache_control=public" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body == "purged=1\n"'
  response="$(client_request "example.test" "/app/admin-json-purge?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/cache/purge" 200 "POST" "{\"type\":\"exact\",\"policy\":\"default\",\"scheme\":\"https\",\"host\":\"example.test\",\"uri\":\"/app/admin-json-purge?cache_control=public\"}" "Authorization: Bearer matrix-admin-token" "Content-Type: application/json")"
  assert_response_jq "${response}" '(.body | fromjson | .purged) == 1'
  docker rm -f "${http_container}" >/dev/null
  response="$(client_request "example.test" "/app/admin-plain-purge?cache_control=public" 502)"
  assert_response_jq "${response}" '.status == 502'
}
