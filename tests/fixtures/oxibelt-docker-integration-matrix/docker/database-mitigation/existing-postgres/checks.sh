
wait_for_existing_mitigation() {
  local status=""
  local count=""
  for _attempt in $(seq 1 30); do
    status="$(postgres_query "SELECT status FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
    count="$(postgres_query "SELECT count FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
    if [[ "${status}" == "pending" && "${count}" == "1" ]]; then
      return 0
    fi
    sleep 1
  done
  fail_with_diagnostics "expected existing mitigation row to reach pending/count=1, got status=${status:-<empty>} count=${count:-<empty>}"
}

run_case_checks() {
  local response row_count count status record_event record_target intent_columns
  response="$(client_request "example.test" "/app/existing-mitigation?case=minimal" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/existing-mitigation?case=minimal"'

  wait_for_existing_mitigation

  row_count="$(postgres_query "SELECT count(*) FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
  count="$(postgres_query "SELECT count FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
  status="$(postgres_query "SELECT status FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
  record_event="$(postgres_query "SELECT record->>'event' FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
  record_target="$(postgres_query "SELECT record->>'target' FROM existing_mitigation_events WHERE namespace = 'matrix-existing' AND record->>'target' = '198.51.100.44';")"
  intent_columns="$(postgres_query "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'existing_mitigation_events' AND column_name = 'intent';")"
  if [[ "${row_count}" != "1" || "${count}" != "1" || "${status}" != "pending" || "${record_event}" != "oxibelt.mitigation" || "${record_target}" != "198.51.100.44" || "${intent_columns}" != "0" ]]; then
    fail_with_diagnostics "unexpected existing mitigation row rows=${row_count} count=${count} status=${status} event=${record_event} target=${record_target} intent_columns=${intent_columns}"
  fi
}
