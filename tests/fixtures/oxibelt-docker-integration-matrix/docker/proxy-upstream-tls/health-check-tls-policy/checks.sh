
run_case_checks() {
  local attempt response state
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/secure-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    if jq -e '.body | fromjson | ([.servers[] | select(.id == "secure" and .healthy == true and .last_health_check_ms != null and .health_reason == "active_success")] | length) == 1' <<<"${state}" >/dev/null; then
      break
    fi
    sleep 0.5
  done
  if ! jq -e '.body | fromjson | ([.servers[] | select(.id == "secure" and .healthy == true and .last_health_check_ms != null and .health_reason == "active_success")] | length) == 1' <<<"${state}" >/dev/null; then
    echo "${state}" >&2
    fail_with_diagnostics "secure upstream active health check did not become healthy"
  fi

  response="$(client_request "secure.example.test" "/secure/tls" 502)"
  assert_response_jq "${response}" '.body == "upstream request failed"'
}
