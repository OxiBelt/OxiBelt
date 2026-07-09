
run_case_checks() {
  local response logs
  response="$(client_request_with_headers "example.test" "/app/system-log?case=ecs" 200 "GET" "" "User-Agent: first-agent" "User-Agent: second-agent")"
  assert_body_jq "${response}" '.path == "/origin/app/system-log?case=ecs"'

  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  if ! jq -R -s -e '
    [split("\n")[] | fromjson?]
    | any(.[]; .ecs.version == "9.4.0"
      and .event.dataset == "oxibelt.access.system"
      and .event.category == ["web"]
      and .event.type == ["access"]
      and .event.outcome == "success"
      and .http.request.method == "GET"
      and .http.response.status_code == 200
      and .url.path == "/app/system-log"
      and .url.query == "case=ecs"
      and .client.ip != null
      and .tls.established == true
      and .user_agent.original == "first-agent"
      and .oxibelt.access.original.scope == "system")
  ' <<<"${logs}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected ECS system access log JSON on stdout"
  fi
  if ! jq -R -s -e '
    [split("\n")[] | fromjson?]
    | any(.[]; .ecs.version == "9.4.0"
      and .oxibelt.access.original.scope == "system"
      and .oxibelt.access.original.path == "/app/system-log"
      and .oxibelt.access.original.status == 200
      and .oxibelt.access.original.user_agent.values == ["first-agent", "second-agent"]
      and .oxibelt.access.original.user_agent.is_truncated == false)
  ' <<<"${logs}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected ECS access log to preserve duplicate User-Agent values"
  fi
}
