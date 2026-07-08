
run_case_checks() {
  local h1 h2 h3 logs

  h1="$(client_request "example.test" "/app/hardened-h1?case=default-seccomp" 200)"
  assert_body_jq "${h1}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .path == "/origin/app/hardened-h1?case=default-seccomp"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'

  h2="$(protocol_probe_client "h2" "example.test" "/app/hardened-h2" 200)"
  assert_response_jq "${h2}" '.negotiated_protocol == "h2"'
  assert_body_jq "${h2}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .path == "/origin/app/hardened-h2"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'

  h3="$(protocol_probe_client "h3" "example.test" "/app/hardened-h3" 200)"
  assert_response_jq "${h3}" '.negotiated_protocol == "h3"'
  assert_body_jq "${h3}" '.upstream == "http-upstream"
    and .request_version == "HTTP/1.1"
    and .path == "/origin/app/hardened-h3"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'

  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  if grep -E 'exited due to signal|signal [0-9]+|SIGSEGV|SIGSYS|segmentation fault' <<<"${logs}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "proxy logged a runtime signal failure"
  fi
}
