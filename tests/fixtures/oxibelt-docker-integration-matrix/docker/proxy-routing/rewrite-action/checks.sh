
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/item/42?debug=true" 200)"
  assert_body_jq "${response}" '.path == "/origin/edge/item/42?id=42&debug=true"'
}
