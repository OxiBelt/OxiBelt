
run_case_checks() {
  local response count
  response="$(client_request_with_headers "example.test" "/app/system-db-log?case=postgres" 200 "GET" "" "User-Agent: first-agent" "User-Agent: second-agent")"
  assert_body_jq "${response}" '.path == "/origin/app/system-db-log?case=postgres"'

  count="$(postgres_query "SELECT count(*) FROM oxibelt_access_log WHERE event = 'oxibelt.access' AND record->>'scope' = 'system' AND record->>'path' = '/app/system-db-log' AND record->>'status' = '200' AND record->>'route' = 'main-route' AND record->'user_agent'->'values' = '[\"first-agent\",\"second-agent\"]'::jsonb AND record->'user_agent'->>'is_truncated' = 'false';")"
  if [[ "${count}" != "1" ]]; then
    fail_with_diagnostics "expected one system PostgreSQL access log row preserving duplicate User-Agent values, got ${count}"
  fi
}
