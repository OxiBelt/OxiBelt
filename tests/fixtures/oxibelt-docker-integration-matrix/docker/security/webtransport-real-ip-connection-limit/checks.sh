
run_case_checks() {
  local holder_log="${work_dir}/held-real-ip-request.json"
  local holder_pid=""
  local response
  local blocked

  protocol_probe_client_with_headers \
    h3 \
    "example.test" \
    "/app/hold?header_delay_ms=15000&body=held" \
    200 \
    "GET" \
    "" \
    "X-Forwarded-For: 203.0.113.77" >"${holder_log}" &
  holder_pid="$!"

  blocked="$(protocol_probe_client_with_headers \
    h3 \
    "example.test" \
    "/app/blocked-while-held" \
    429 \
    "GET" \
    "" \
    "X-Forwarded-For: 203.0.113.77")"
  assert_response_jq "${blocked}" '.status == 429'

  response="$(protocol_probe_webtransport_multiplex \
    "example.test" \
    "/wt/session" \
    1 \
    "429" \
    --header "X-Forwarded-For: 203.0.113.77")"
  assert_response_jq "${response}" '.statuses == [429]'

  if ! wait "${holder_pid}"; then
    cat "${holder_log}" >&2 || true
    fail_with_diagnostics "held Real-IP request failed"
  fi

  response="$(protocol_probe_webtransport_multiplex \
    "example.test" \
    "/wt/session-after-release" \
    1 \
    "200" \
    --header "X-Forwarded-For: 203.0.113.77")"
  assert_response_jq "${response}" '.statuses == [200]'
}
