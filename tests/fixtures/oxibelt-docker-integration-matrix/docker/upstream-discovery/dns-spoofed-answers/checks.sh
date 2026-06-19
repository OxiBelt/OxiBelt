
run_case_checks() {
  local response
  sleep 2

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/spoof-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '(.body | fromjson | [.servers[] | select(.source == "dns")] | length) == 0'

  response="$(client_request "spoof.example.test" "/app/spoof-static" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/spoof-static"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/valid-dns-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '(.body | fromjson | [.servers[] | select(.source == "dns")] | length) == 1'

  response="$(client_request "valid.example.test" "/app/valid-dns" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/app/valid-dns"'
}
