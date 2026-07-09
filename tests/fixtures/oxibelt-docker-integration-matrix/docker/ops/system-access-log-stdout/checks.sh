
run_case_checks() {
  local response logs
  response="$(client_request_with_headers "example.test" "/app/system-log?case=stdout" 200 "GET" "" "User-Agent: first-agent" "User-Agent: second-agent")"
  assert_body_jq "${response}" '.path == "/origin/app/system-log?case=stdout"'

  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  if ! jq -R -s -e '
    [split("\n")[] | fromjson?]
    | any(.[]; .class_uid == 4002
      and .unmapped.oxibelt.scope == "system"
      and .unmapped.oxibelt.path == "/app/system-log"
      and .unmapped.oxibelt.status == 200)
  ' <<<"${logs}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected system access log JSON on stdout"
  fi
  if ! jq -R -s -e '
    [split("\n")[] | fromjson?]
    | any(.[]; .class_uid == 4002
      and .unmapped.oxibelt.scope == "system"
      and .unmapped.oxibelt.path == "/app/system-log"
      and .unmapped.oxibelt.status == 200
      and .unmapped.oxibelt.user_agent.values == ["first-agent", "second-agent"]
      and .unmapped.oxibelt.user_agent.is_truncated == false)
  ' <<<"${logs}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected system access log to preserve duplicate User-Agent values"
  fi
}
