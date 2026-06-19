
run_case_checks() {
  local host_miss path_miss
  host_miss="$(client_request "other.example.test" "/app/known" 404)"
  assert_response_jq "${host_miss}" '.body == "no matching route"'

  path_miss="$(client_request "example.test" "/other" 404)"
  assert_response_jq "${path_miss}" '.body == "no matching route"'
}
