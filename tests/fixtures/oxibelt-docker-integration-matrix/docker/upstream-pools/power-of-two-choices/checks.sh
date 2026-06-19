
run_case_checks() {
  local first second
  first="$(client_request "example.test" "/app/pool-a" 200)"
  second="$(client_request "example.test" "/app/pool-b" 200)"
  assert_body_jq "${first}" '.upstream == "http-upstream" or .upstream == "alt-upstream"'
  assert_body_jq "${second}" '.upstream == "http-upstream" or .upstream == "alt-upstream"'
}
