
run_case_checks() {
  local public_response cookie_response auth_response set_cookie_response private_response

  public_response="$(client_request_with_headers "example.test" "/app/public?case=gzip" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${public_response}" '.headers["content-encoding"] == "gzip"
    and .headers["content-length"] == null'

  cookie_response="$(client_request_with_headers "example.test" "/app/auth-cookie?case=cookie" 200 "GET" "" "Accept-Encoding: gzip" "Cookie: session=secret")"
  assert_response_jq "${cookie_response}" '.headers["content-encoding"] == null'
  assert_body_jq "${cookie_response}" '.headers.cookie == "session=secret"'

  auth_response="$(client_request_with_headers "example.test" "/app/auth-header?case=authorization" 200 "GET" "" "Accept-Encoding: gzip" "Authorization: Bearer secret")"
  assert_response_jq "${auth_response}" '.headers["content-encoding"] == null'
  assert_body_jq "${auth_response}" '.headers.authorization == "Bearer secret"'

  set_cookie_response="$(client_request_with_headers "example.test" "/app/set-cookie?set_cookie=1" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${set_cookie_response}" '.headers["content-encoding"] == null
    and .headers["set-cookie"] == "upstream_session=present; Path=/"'
  assert_body_jq "${set_cookie_response}" '.path == "/origin/app/set-cookie?set_cookie=1"'

  private_response="$(client_request_with_headers "example.test" "/app/private?cache_control=private-no-store" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${private_response}" '.headers["content-encoding"] == null
    and .headers["cache-control"] == "private, no-store"'
  assert_body_jq "${private_response}" '.path == "/origin/app/private?cache_control=private-no-store"'
}
