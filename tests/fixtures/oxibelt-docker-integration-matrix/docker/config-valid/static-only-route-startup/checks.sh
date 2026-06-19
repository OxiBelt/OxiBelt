
run_case_checks() {
  local response
  response="$(client_request "static.example.test" "/assets/ok.txt" 200)"
  assert_response_jq "${response}" '.body == "static ok\n"'
}
