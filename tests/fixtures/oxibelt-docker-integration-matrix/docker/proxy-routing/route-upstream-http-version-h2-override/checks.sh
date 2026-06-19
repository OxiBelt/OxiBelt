
run_case_checks() {
  local response
  response="$(client_request "example.test" "/h2/override" 200)"
  assert_body_jq "${response}" '.upstream == "h2-upstream"
    and .request_version == "HTTP/2.0"
    and .path == "/h2-origin/h2/override"'
}
