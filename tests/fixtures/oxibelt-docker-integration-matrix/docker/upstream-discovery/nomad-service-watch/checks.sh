
run_case_checks() {
  local response state metrics attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/nomad-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    if jq -e '.body | fromjson | ([.servers[] | select(.source == "nomad" and (.origin | contains(":18080/")) and .health_reason == "unknown" and (.effective_weight_percent >= 10) and (.effective_weight_percent <= 100) and (.slow_start_remaining_ms != null))] | length) == 1' <<<"${state}" >/dev/null; then
      response="$(client_request "nomad.example.test" "/app/nomad-initial-${attempt}" 200)"
      if jq -e '.body | fromjson | .upstream == "http-upstream"' <<<"${response}" >/dev/null; then
        break
      fi
    fi
    sleep 0.5
  done
  if ! jq -e '.body | fromjson | .upstream == "http-upstream"' <<<"${response}" >/dev/null; then
    echo "${state}" >&2
    echo "${response}" >&2
    fail_with_diagnostics "Nomad initial service list did not route to the HTTP upstream"
  fi

  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/nomad-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    if jq -e '.body | fromjson | ([.servers[] | select(.source == "nomad" and (.origin | contains(":18081/")) and (.ejection_count == 0) and (.ejected_until_ms == null) and (.last_health_check_ms == null))] | length) == 1' <<<"${state}" >/dev/null; then
      response="$(client_request "nomad.example.test" "/app/nomad-watch-${attempt}" 200)"
      if jq -e '.body | fromjson | .upstream == "alt-upstream"' <<<"${response}" >/dev/null; then
        break
      fi
    fi
    sleep 0.5
  done
  if ! jq -e '.body | fromjson | .upstream == "alt-upstream"' <<<"${response}" >/dev/null; then
    echo "${state}" >&2
    echo "${response}" >&2
    fail_with_diagnostics "Nomad blocking query update did not route to the alternate upstream"
  fi

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_upstream_pool_servers")'
  assert_response_jq "${metrics}" '.body | contains("source=\"nomad\"")'
  assert_response_jq "${metrics}" '.body | contains("reason=\"passive_success\"")'
  assert_response_jq "${metrics}" '.body | contains("matrix-nomad-token") | not'
  assert_response_jq "${metrics}" '.body | contains("mock-nomad") | not'
  assert_response_jq "${metrics}" '.body | contains("nomad-app-") | not'
  assert_response_jq "${metrics}" '.body | contains("172.18.") | not'
  assert_response_jq "${metrics}" '.body | contains("http://") | not'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/nomad-pool" 401 "GET" "" "Authorization: Bearer wrong-token")"
  assert_response_jq "${response}" '.body | fromjson | .error.code == "unauthorized"'
}
