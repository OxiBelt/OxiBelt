run_case_checks() {
  local response="" state="" logs="" attempt=""
  local baseline_rejection_count=0 rejection_count=0
  local restart_only_reason="full hot reload rejected because SecP256r1MLKEM768 TLS key-exchange policy is restart-only"

  wait_for_discovered_server() {
    for ((attempt = 1; attempt <= 30; attempt++)); do
      state="$(plain_client_request_with_headers_on_port \
        9092 "proxy" "/admin/v1/upstream-pools/app-pool" 200 "GET" "" \
        "Authorization: Bearer matrix-admin-token")"
      if jq -e '
        .body | fromjson |
        ([.servers[] | select(.id == "primary" and .source == "static" and .state == "down")] | length) == 1 and
        ([.servers[] | select(.source == "file" and .origin == "https://mock-https:18443/backend" and .state == "ready" and .healthy == true)] | length) == 1
      ' <<<"${state}" >/dev/null; then
        return 0
      fi
      sleep 0.5
    done
    echo "${state}" >&2
    fail_with_diagnostics "file-discovered HTTPS endpoint did not become healthy alongside the static down fallback"
  }

  wait_for_reloaded_waf() {
    for ((attempt = 1; attempt <= 30; attempt++)); do
      response="$(client_request_with_headers_to_target \
        "proxy" 8443 "example.test" "/app/reloaded" "200,403,503" "GET" "")"
      if jq -e '.status == 403 and .body == "reloaded WAF"' <<<"${response}" >/dev/null; then
        return 0
      fi
      sleep 0.5
    done
    echo "${response}" >&2
    fail_with_diagnostics "unrelated WAF change did not become visible after full hot reload"
  }

  wait_for_restart_only_rejection() {
    for ((attempt = 1; attempt <= 30; attempt++)); do
      logs="$(docker logs "${proxy_container}" 2>&1 || true)"
      rejection_count="$(grep -F -c "${restart_only_reason}" <<<"${logs}" || true)"
      if (( rejection_count > baseline_rejection_count )); then
        return 0
      fi
      sleep 0.5
    done
    echo "${logs}" >&2
    fail_with_diagnostics "full hot reload did not reject the discovered PQ toggle with the restart-only reason"
  }

  wait_for_discovered_server
  if ! response="$(client_request "example.test" "/app/discovered" 200)"; then
    fail_with_diagnostics "file-discovered HTTPS endpoint did not serve traffic"
  fi
  assert_body_jq "${response}" '.scheme == "https" and .upstream == "https-upstream"'
  response="$(client_request "example.test" "/app/reloaded" 200)"
  assert_body_jq "${response}" '.scheme == "https" and .upstream == "https-upstream"'

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy
  wait_for_reloaded_waf
  wait_for_discovered_server

  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  baseline_rejection_count="$(grep -F -c "${restart_only_reason}" <<<"${logs}" || true)"

  docker cp "${case_dir}/config/toggle-discovery-pq.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy
  wait_for_restart_only_rejection

  wait_for_discovered_server
  response="$(client_request_with_headers_to_target \
    "proxy" 8443 "example.test" "/app/reloaded" "200,403" "GET" "")"
  if ! jq -e '.status == 403 and .body == "reloaded WAF"' <<<"${response}" >/dev/null; then
    echo "${response}" >&2
    fail_with_diagnostics "rejected PQ toggle changed the previously active WAF state"
  fi
}
