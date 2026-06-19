
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/download?file=%2e%2e%2fetc%2fpasswd" 403)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'

  response="$(client_request "example.test" "/app/search?q=UNION%20SELECT" 403)"
  assert_response_jq "${response}" '.body == "Blocked by CRS"'
}
