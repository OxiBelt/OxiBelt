
run_case_checks() {
  local first second first_instance second_instance
  first="$(protocol_probe_client "h2" "example.test" "/app/reconnect-before" 200)"
  assert_body_jq "${first}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/3.0"
    and .path == "/h3-origin/app/reconnect-before"'

  docker restart "${h3_container}" >/dev/null

  second="$(protocol_probe_client "h2" "example.test" "/app/reconnect-after" 200)"
  assert_body_jq "${second}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .request_version == "HTTP/3.0"
    and .path == "/h3-origin/app/reconnect-after"'
  first_instance="$(jq -r '.body | fromjson | .instance_id' <<<"${first}")"
  second_instance="$(jq -r '.body | fromjson | .instance_id' <<<"${second}")"
  if [[ "${first_instance}" == "${second_instance}" ]]; then
    echo "expected pooled upstream H3 request to reach a restarted upstream instance; got ${first_instance}" >&2
    fail_with_diagnostics "upstream H3 pool did not reconnect after upstream restart"
  fi
}
