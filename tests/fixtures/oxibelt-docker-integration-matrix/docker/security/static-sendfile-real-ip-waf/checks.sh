
run_case_checks() {
  local allowed plain_blocked https_blocked

  allowed="$(plain_client_request "static-real-ip.example.test" "/static/ok.txt" 200)"
  assert_response_jq "${allowed}" '.body == "static ok\n"'

  plain_blocked="$(plain_client_request_with_headers_on_port 8080 "static-real-ip.example.test" "/static/ok.txt" 451 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_response_jq "${plain_blocked}" '.body == "real ip blocked"'

  https_blocked="$(client_request_with_headers "static-real-ip.example.test" "/static/ok.txt" 451 "GET" "" "X-Forwarded-For: 203.0.113.10")"
  assert_response_jq "${https_blocked}" '.body == "real ip blocked"'
}
