
run_case_checks() {
  local response purge replay
  response="$(client_request "example.test" "/app/signed-purge?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'

  purge="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/signed-purge?cache_control=public" 200 "POST" "" \
    "X-OxiBelt-Cache-Timestamp: 1700000000" \
    "X-OxiBelt-Cache-Nonce: matrix-signed-purge" \
    "X-OxiBelt-Cache-Signature: 8PmsDoehRk/B9RyQnNWI9mWFMgXw6brivm7pa/5Da08=")"
  assert_response_jq "${purge}" '.body == "purged=1\n"'

  replay="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/signed-purge?cache_control=public" 401 "POST" "" \
    "X-OxiBelt-Cache-Timestamp: 1700000000" \
    "X-OxiBelt-Cache-Nonce: matrix-signed-purge" \
    "X-OxiBelt-Cache-Signature: 8PmsDoehRk/B9RyQnNWI9mWFMgXw6brivm7pa/5Da08=")"
  assert_response_jq "${replay}" '(.body | fromjson) as $body | $body.error.code == "unauthorized" and $body.error.message == "unauthorized"'
}
