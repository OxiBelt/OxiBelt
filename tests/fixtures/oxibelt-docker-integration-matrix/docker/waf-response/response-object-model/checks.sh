
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/response-object?set_cookie=1" 200)"
  assert_response_jq "${response}" '.headers["x-waf-response-object"] == "matched"
    and (.headers["set-cookie"] | contains("upstream_session=present"))'
  assert_body_jq "${response}" '.upstream == "http-upstream"
    and .path == "/origin/app/response-object?set_cookie=1"'
}
