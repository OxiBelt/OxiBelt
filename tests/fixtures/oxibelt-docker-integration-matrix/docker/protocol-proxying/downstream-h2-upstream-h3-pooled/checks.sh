
run_case_checks() {
  local first second first_id second_id
  first="$(protocol_probe_client "h2" "example.test" "/app/pooled-first" 200)"
  second="$(protocol_probe_client "h2" "example.test" "/app/pooled-second" 200)"
  assert_body_jq "${first}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/3.0"
    and .path == "/h3-origin/app/pooled-first"'
  assert_body_jq "${second}" '.path == "/h3-origin/app/pooled-second"'
  first_id="$(jq -r '.body | fromjson | .connection_id' <<<"${first}")"
  second_id="$(jq -r '.body | fromjson | .connection_id' <<<"${second}")"
  if [[ "${first_id}" != "${second_id}" ]]; then
    echo "expected pooled upstream H3 connection id to be reused; got ${first_id} then ${second_id}" >&2
    fail_with_diagnostics "upstream H3 pool did not reuse the connection"
  fi
}
