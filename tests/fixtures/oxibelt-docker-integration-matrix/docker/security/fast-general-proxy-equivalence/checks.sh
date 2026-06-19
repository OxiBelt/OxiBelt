
assert_security_headers() {
  local response="$1"
  assert_response_jq "${response}" '.headers["strict-transport-security"] == "max-age=63072000; includeSubDomains; preload"'
  assert_response_jq "${response}" '.headers["x-content-type-options"] == "nosniff"'
  assert_response_jq "${response}" '.headers["referrer-policy"] == "no-referrer"'
  assert_response_jq "${response}" '.headers["permissions-policy"] == "geolocation=(), camera=()"'
}

assert_same_body_projection() {
  local left="$1"
  local right="$2"
  local filter="$3"
  local left_value right_value
  left_value="$(jq -c ".body | fromjson | ${filter}" <<<"${left}")"
  right_value="$(jq -c ".body | fromjson | ${filter}" <<<"${right}")"
  if [[ "${left_value}" != "${right_value}" ]]; then
    echo "fast projection: ${left_value}" >&2
    echo "general projection: ${right_value}" >&2
    fail_with_diagnostics "fast/general upstream observations diverged"
  fi
}

run_case_checks() {
  local fast general fast_bad general_bad

  fast="$(client_request "example.test" "/fast/echo?case=get" 200)"
  general="$(client_request "example.test" "/general/echo?case=get" 200)"
  assert_security_headers "${fast}"
  assert_security_headers "${general}"
  assert_same_body_projection "${fast}" "${general}" '{method, path, body, headers: {
    host: .headers.host,
    "x-forwarded-host": .headers["x-forwarded-host"],
    "x-forwarded-proto": .headers["x-forwarded-proto"]
  }}'

  fast="$(client_request_with_headers "example.test" "/fast/post?case=body" 200 "POST" "posted body" "Content-Type: text/plain")"
  general="$(client_request_with_headers "example.test" "/general/post?case=body" 200 "POST" "posted body" "Content-Type: text/plain")"
  assert_same_body_projection "${fast}" "${general}" '{method, path, body, headers: {
    "content-type": .headers["content-type"],
    "content-length": .headers["content-length"]
  }}'

  fast="$(client_request_with_headers "example.test" "/fast/hop" 200 "GET" "" \
    "Connection: X-Remove-Hop, keep-alive" \
    "X-Remove-Hop: remove-me" \
    "Proxy-Authorization: Basic remove-me" \
    "Proxy-Authenticate: remove-me" \
    "Keep-Alive: timeout=5")"
  general="$(client_request_with_headers "example.test" "/general/hop" 200 "GET" "" \
    "Connection: X-Remove-Hop, keep-alive" \
    "X-Remove-Hop: remove-me" \
    "Proxy-Authorization: Basic remove-me" \
    "Proxy-Authenticate: remove-me" \
    "Keep-Alive: timeout=5")"
  assert_same_body_projection "${fast}" "${general}" '{path, headers: {
    connection: .headers.connection,
    "x-remove-hop": .headers["x-remove-hop"],
    "proxy-authorization": .headers["proxy-authorization"],
    "proxy-authenticate": .headers["proxy-authenticate"],
    "keep-alive": .headers["keep-alive"]
  }}'
  assert_body_jq "${fast}" '.headers.connection == null
    and .headers["x-remove-hop"] == null
    and .headers["proxy-authorization"] == null
    and .headers["proxy-authenticate"] == null
    and .headers["keep-alive"] == null'

  fast="$(client_request_with_headers "example.test" "/fast/forwarded" 200 "GET" "" \
    "Forwarded: for=198.51.100.1;proto=http;host=evil.test" \
    "X-Forwarded-For: 198.51.100.1" \
    "X-Forwarded-Host: evil.test" \
    "X-Forwarded-Proto: http" \
    "X-Forwarded-Port: 80")"
  general="$(client_request_with_headers "example.test" "/general/forwarded" 200 "GET" "" \
    "Forwarded: for=198.51.100.1;proto=http;host=evil.test" \
    "X-Forwarded-For: 198.51.100.1" \
    "X-Forwarded-Host: evil.test" \
    "X-Forwarded-Proto: http" \
    "X-Forwarded-Port: 80")"
  assert_same_body_projection "${fast}" "${general}" '{path, headers: {
    host: .headers.host,
    forwarded: .headers.forwarded,
    "x-forwarded-host": .headers["x-forwarded-host"],
    "x-forwarded-proto": .headers["x-forwarded-proto"]
  }}'
  assert_body_jq "${fast}" '.headers.forwarded == null
    and (.headers["x-forwarded-for"] | contains("198.51.100.1") | not)
    and .headers["x-forwarded-host"] == "example.test"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-port"] == "443"
    and (.headers.host | startswith("mock-http:18080"))'
  assert_body_jq "${general}" '.headers.forwarded == null
    and (.headers["x-forwarded-for"] | contains("198.51.100.1") | not)
    and .headers["x-forwarded-port"] == "443"'

  fast_bad="$(chunked_body_client_request "example.test" "/fast/ambiguous" 400 "POST" "abcd" "Content-Type: text/plain" "Content-Length: 4")"
  general_bad="$(chunked_body_client_request "example.test" "/general/ambiguous" 400 "POST" "abcd" "Content-Type: text/plain" "Content-Length: 4")"
  assert_response_jq "${fast_bad}" '.status == 400'
  assert_response_jq "${general_bad}" '.status == 400'

  protocol_probe_generated_body_request_expect_error "h2" "example.test" "/fast/h2-cl0-data" "POST" 8 4 "stream error received: unspecific protocol error detected" --omit-content-length --header "Content-Length: 0"
  protocol_probe_generated_body_request_expect_error "h2" "example.test" "/general/h2-cl0-data" "POST" 8 4 "stream error received: unspecific protocol error detected" --omit-content-length --header "Content-Length: 0"

  fast_bad="$(protocol_probe_generated_body_request "h3" "example.test" "/fast/h3-cl0-data" "POST" 8 4 --omit-content-length --header "Content-Length: 0" --expect-status 413)"
  general_bad="$(protocol_probe_generated_body_request "h3" "example.test" "/general/h3-cl0-data" "POST" 8 4 --omit-content-length --header "Content-Length: 0" --expect-status 413)"
  assert_response_jq "${fast_bad}" '.body == "request body is too large"'
  assert_response_jq "${general_bad}" '.body == "request body is too large"'
}
