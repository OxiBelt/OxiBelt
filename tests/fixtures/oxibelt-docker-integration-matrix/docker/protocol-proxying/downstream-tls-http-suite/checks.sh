
run_case_checks() {
  local h1 h2 h3
  h1="$(client_request "example.test" "/app/h1-suite?case=forwarded" 200)"
  assert_body_jq "${h1}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .path == "/origin/app/h1-suite?case=forwarded"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'

  h2="$(protocol_probe_client "h2" "example.test" "/app/h2-suite" 200)"
  assert_response_jq "${h2}" '.negotiated_protocol == "h2"'
  assert_body_jq "${h2}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .path == "/origin/app/h2-suite"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'

  h3="$(protocol_probe_client "h3" "example.test" "/app/h3-suite" 200)"
  assert_response_jq "${h3}" '.negotiated_protocol == "h3"'
  assert_body_jq "${h3}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .path == "/origin/app/h3-suite"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'
}
