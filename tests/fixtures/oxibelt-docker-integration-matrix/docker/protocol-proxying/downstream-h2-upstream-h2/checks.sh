
run_case_checks() {
  local response
  response="$(protocol_probe_client "h2" "example.test" "/app/downstream-h2-upstream-h2" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h2"'
  assert_body_jq "${response}" '.upstream == "h2-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/2.0"
    and .path == "/h2-origin/app/downstream-h2-upstream-h2"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'
}
      