
run_case_checks() {
  local path warm cached
  path="/app/warm?body=warmed&cache_control=public&content_type=text/plain"
  warm="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/cache/warm" 200 "POST" "{\"items\":[{\"scheme\":\"https\",\"host\":\"example.test\",\"uri\":\"${path}\"}]}" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${warm}" '(.body | fromjson | .items[0].result) == "stored"'

  docker rm -f "${http_container}" >/dev/null
  cached="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${cached}" '.body == "warmed"'
}
