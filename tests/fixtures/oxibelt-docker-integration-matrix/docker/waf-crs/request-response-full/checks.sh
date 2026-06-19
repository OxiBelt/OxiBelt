
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/phase1" 403 "GET" "" "User-Agent: phase1-probe")"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(split_body_client_request "example.test" "/app/phase2" 403 "POST" "prefix body-threat suffix" 10 100 "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(client_request "example.test" "/app/encoding-safe?q=%E2%9C%93%20ok" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/encoding-safe?q=%E2%9C%93%20ok"'

  response="$(client_request "example.test" "/app/malformed-url?q=%ZZ" 403)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(client_request "example.test" "/app/invalid-utf8?q=%C0%AF" 403)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(client_request "example.test" "/app/phase3?content_type=text/crs-phase3&body=safe" 502)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(client_request "example.test" "/app/phase4?content_type=text/plain&body=prefix-secret-leak-suffix" 502)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'
}
