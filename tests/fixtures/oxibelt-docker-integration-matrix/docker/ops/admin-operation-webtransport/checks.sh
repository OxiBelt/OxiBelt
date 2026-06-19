
operation_json() {
  local id="$1"
  local response
  response="$(client_request_with_headers_on_port 9092 "proxy" "/admin/v1/operations/${id}" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  jq -c '.body | fromjson' <<<"${response}"
}

wait_operation_phase() {
  local id="$1"
  local expected="$2"
  local attempt state phase operation
  for attempt in $(seq 1 80); do
    operation="$(operation_json "${id}")"
    state="$(jq -r '.state' <<<"${operation}")"
    phase="$(jq -r '.progress.phase // ""' <<<"${operation}")"
    if [[ "${phase}" == "${expected}" ]]; then
      return 0
    fi
    if [[ "${state}" == "failed" || "${state}" == "cancelled" ]]; then
      echo "${operation}" >&2
      fail_with_diagnostics "operation ${id} reached terminal state before phase ${expected}"
    fi
    sleep 0.1
  done
  operation="$(operation_json "${id}")"
  echo "${operation}" >&2
  fail_with_diagnostics "operation ${id} did not reach phase ${expected}"
}

wait_operation_state() {
  local id="$1"
  local expected="$2"
  local attempt state operation
  for attempt in $(seq 1 80); do
    operation="$(operation_json "${id}")"
    state="$(jq -r '.state' <<<"${operation}")"
    if [[ "${state}" == "${expected}" ]]; then
      printf '%s' "${operation}"
      return 0
    fi
    sleep 0.1
  done
  operation="$(operation_json "${id}")"
  echo "${operation}" >&2
  fail_with_diagnostics "operation ${id} did not reach state ${expected}"
}

run_case_checks() {
  local drain_body drain drain_id events events_file events_pid rejected terminal

  drain_body='{"kind":"webtransport_drain","request":{"scope":{"route":"webtransport-route"},"grace_ms":8000,"close_code":0,"reason":"matrix drain"}}'
  drain="$(client_request_with_headers_on_port 9092 "proxy" "/admin/v1/operations" 202 "POST" "${drain_body}" "Authorization: Bearer matrix-admin-token" "Content-Type: application/json")"
  drain_id="$(jq -r '.body | fromjson | .id' <<<"${drain}")"
  wait_operation_phase "${drain_id}" "grace"

  events_file="${work_dir}/admin-operation-wt-events.json"
  protocol_probe_admin_operation_wt_events "/admin/v1/operations/${drain_id}/events/wt" "operation.result" "succeeded" >"${events_file}" &
  events_pid="$!"
  sleep 1

  rejected="$(protocol_probe_webtransport_multiplex "example.test" "/wt/session" 1 "503")"
  jq -e '.statuses == [503]' <<<"${rejected}" >/dev/null

  if ! wait "${events_pid}"; then
    cat "${events_file}" >&2 || true
    fail_with_diagnostics "Admin WebTransport operation event probe did not reach succeeded drain terminal state"
  fi
  events="$(cat "${events_file}")"
  jq -e '.events | index("operation.result") != null' <<<"${events}" >/dev/null

  terminal="$(wait_operation_state "${drain_id}" "succeeded")"
  jq -e '.result.grace_ms == 8000 and (.result.close_sent | type == "number")' <<<"${terminal}" >/dev/null
}
