
run_case_checks() {
  local response logs matching
  response="$(client_request_with_headers "example.test" "/app/system-log?case=stdout" 200 "GET" "" "User-Agent: first-agent" "User-Agent: second-agent")"
  assert_body_jq "${response}" '.path == "/origin/app/system-log?case=stdout"'

  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  matching="$(grep -F '"class_uid":4002' <<<"${logs}" | grep -F '"scope":"system"' | grep -F '"path":"/app/system-log"' | grep -F '"status":200' || true)"
  if [[ -z "${matching}" ]]; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected system access log JSON on stdout"
  fi
  if ! grep -F '"user_agent":{"values":["first-agent","second-agent"],"is_truncated":false}' <<<"${matching}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected system access log to preserve duplicate User-Agent values"
  fi
}
