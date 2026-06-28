
assert_default_security_policy() {
  local response="$1"
  assert_response_jq "${response}" '.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains; preload"'
  assert_response_jq "${response}" '.headers["x-content-type-options"] == "nosniff"'
  assert_response_jq "${response}" '.headers["referrer-policy"] == "no-referrer"'
  assert_response_jq "${response}" '.headers["permissions-policy"] == "geolocation=(), camera=()"'
}

assert_api_security_policy() {
  local response="$1"
  assert_response_jq "${response}" '.headers["strict-transport-security"] == "max-age=15768000"'
  assert_response_jq "${response}" '.headers["x-content-type-options"] == "api-nosniff"'
  assert_response_jq "${response}" '.headers["referrer-policy"] == "same-origin"'
  assert_response_jq "${response}" '.headers["permissions-policy"] == "microphone=()"'
}

assert_static_security_policy() {
  local response="$1"
  assert_response_jq "${response}" '.headers["strict-transport-security"] == null'
  assert_response_jq "${response}" '.headers["x-content-type-options"] == "static-nosniff"'
  assert_response_jq "${response}" '.headers["referrer-policy"] == "strict-origin"'
  assert_response_jq "${response}" '.headers["permissions-policy"] == null'
}

assert_no_security_policy() {
  local response="$1"
  assert_response_jq "${response}" '.headers["strict-transport-security"] == null'
  assert_response_jq "${response}" '.headers["x-content-type-options"] == null'
  assert_response_jq "${response}" '.headers["referrer-policy"] == null'
  assert_response_jq "${response}" '.headers["permissions-policy"] == null'
}

run_case_checks() {
  local response

  response="$(client_request "example.test" "/app/security-headers" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/security-headers"'
  assert_default_security_policy "${response}"

  response="$(client_request "example.test" "/api/security-headers" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/api/security-headers"'
  assert_api_security_policy "${response}"

  response="$(client_request "example.test" "/off/security-headers" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/off/security-headers"'
  assert_no_security_policy "${response}"

  response="$(client_request "example.test" "/static/static.txt" 200)"
  assert_response_jq "${response}" '.body == "static security headers\n"'
  assert_static_security_policy "${response}"

  response="$(client_request "example.test" "/terminal/security-headers" 451)"
  assert_response_jq "${response}" '.body == "blocked by security header test"'
  assert_api_security_policy "${response}"

  response="$(client_request "example.test" "/redirect/old?debug=true" 308)"
  assert_response_jq "${response}" '.headers.location == "/new/old?debug=true"'
  assert_api_security_policy "${response}"
}
