
run_case_checks() {
  local broad narrow
  broad="$(client_request "www.example.test" "/suffix/broad" 200)"
  assert_body_jq "${broad}" '.upstream == "http-upstream" and .path == "/origin/suffix/broad"'

  narrow="$(client_request "v1.api.example.test" "/suffix/narrow" 200)"
  assert_body_jq "${narrow}" '.upstream == "alt-upstream" and .path == "/alt/suffix/narrow"'
}
