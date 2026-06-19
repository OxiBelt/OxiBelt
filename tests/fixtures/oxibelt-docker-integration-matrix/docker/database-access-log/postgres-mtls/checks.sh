
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/db-log?case=mtls" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/db-log?case=mtls"'

  local count
  count="$(postgres_query "SELECT count(*) FROM oxibelt_access_log WHERE event = 'oxibelt.access' AND record->>'path' = '/app/db-log' AND record->>'status' = '200' AND record->>'route' = 'main-route';")"
  if [[ "${count}" != "1" ]]; then
    fail_with_diagnostics "expected one PostgreSQL access log row, got ${count}"
  fi
}
