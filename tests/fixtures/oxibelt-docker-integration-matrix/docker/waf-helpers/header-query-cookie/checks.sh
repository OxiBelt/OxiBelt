
run_case_checks() {
  local response
  response="$(client_request_with_headers "example.test" "/app/helpers?block=yes" 418 "GET" "" "X-Matrix-Case: yes" "Cookie: matrix=cookie")"
  assert_response_jq "${response}" '.body == "helper matched"'
}
