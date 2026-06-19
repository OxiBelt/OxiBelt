
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/security-headers" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/security-headers"'
  assert_response_jq "${response}" '.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains; preload"'
  assert_response_jq "${response}" '.headers["x-content-type-options"] == "nosniff"'
  assert_response_jq "${response}" '.headers["referrer-policy"] == "no-referrer"'
  assert_response_jq "${response}" '.headers["permissions-policy"] == "geolocation=(), camera=()"'
}
