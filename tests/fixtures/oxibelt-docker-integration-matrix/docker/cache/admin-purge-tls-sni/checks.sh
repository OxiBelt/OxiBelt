
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/admin-purge?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'
  response="$(client_request "example.test" "/app/admin-purge?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "hit" and .headers["x-oxibelt-cache-reason"] == "fresh"'
  response="$(client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/admin-purge?cache_control=public" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body == "purged=1\n"'
  docker rm -f "${http_container}" >/dev/null
  response="$(client_request "example.test" "/app/admin-purge?cache_control=public" 502)"
  assert_response_jq "${response}" '.status == 502'
}
