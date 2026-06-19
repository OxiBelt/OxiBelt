
run_case_checks() {
  local response
  response="$(client_request "example.test" "/route-enable" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream"'
}
