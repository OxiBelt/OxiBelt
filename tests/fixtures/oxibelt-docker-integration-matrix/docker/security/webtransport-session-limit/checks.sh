
run_case_checks() {
  local response
  response="$(protocol_probe_webtransport_multiplex "example.test" "/wt/session" 2 "200,429")"
  assert_response_jq "${response}" '.statuses == [200, 429]'
}
