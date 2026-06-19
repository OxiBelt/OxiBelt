
run_case_checks() {
  local response state
  response="$(client_request "example.test" "/route-disable" 503)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'

  state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${state}" '.body | fromjson | ([.servers[] | select(.id == "bad" and .healthy == true)] | length) == 1'
}
