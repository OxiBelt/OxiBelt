
run_case_checks() {
  local response state
  response="$(client_request "example.test" "/connect-policy" 502)"
  assert_response_jq "${response}" '.status == 502'

  state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${state}" '.body | fromjson | ([.servers[] | select(.id == "bad" and .healthy == true)] | length) == 1'
}
