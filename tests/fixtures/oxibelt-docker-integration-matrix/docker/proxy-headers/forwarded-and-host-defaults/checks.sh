
run_case_checks() {
  local response
  response="$(
    client_request_with_headers "example.test" "/app/headers" 200 "GET" "" \
      "Forwarded: for=198.51.100.1;proto=http;host=evil.test" \
      "X-Forwarded-For: 198.51.100.1" \
      "X-Forwarded-Host: evil.test" \
      "X-Forwarded-Proto: http" \
      "X-Forwarded-Port: 80"
  )"
  assert_body_jq "${response}" '.headers.forwarded == null
    and (.headers["x-forwarded-for"] | contains("198.51.100.1") | not)
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"
    and .headers["x-forwarded-port"] == "443"
    and (.headers.host | startswith("mock-http:18080"))'
}
