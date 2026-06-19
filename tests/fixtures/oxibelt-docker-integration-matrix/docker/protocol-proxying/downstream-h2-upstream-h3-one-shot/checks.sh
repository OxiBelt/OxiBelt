
run_case_checks() {
  local first second first_id second_id
  first="$(protocol_probe_client "h2" "example.test" "/app/one-shot-first" 200)"
  second="$(protocol_probe_client_with_headers "h2" "example.test" "/app/one-shot-post" 200 "POST" "one-shot-body")"
  assert_body_jq "${first}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/3.0"
    and .path == "/h3-origin/app/one-shot-first"'
  assert_body_jq "${second}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/3.0"
    and .method == "POST"
    and .path == "/h3-origin/app/one-shot-post"
    and .body == "one-shot-body"'
  first_id="$(jq -r '.body | fromjson | .connection_id' <<<"${first}")"
  second_id="$(jq -r '.body | fromjson | .connection_id' <<<"${second}")"
  if [[ "${first_id}" == "${second_id}" ]]; then
    echo "expected one-shot upstream H3 connection id to change; both requests used ${first_id}" >&2
    fail_with_diagnostics "one-shot upstream H3 reused the connection"
  fi
}
