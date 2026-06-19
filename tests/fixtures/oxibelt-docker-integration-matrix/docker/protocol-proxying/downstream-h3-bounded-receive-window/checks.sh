
run_case_checks() {
  local response
  response="$(protocol_probe_generated_body_request "h3" "example.test" "/app/bounded-window" "POST" 65536 8192 --expect-status 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3"'
  assert_body_jq "${response}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .method == "POST"
    and .path == "/origin/app/bounded-window"
    and (.body | length) == 65536'
}
