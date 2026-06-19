
run_case_checks() {
  local h1 h2
  h1="$(client_request "example.test" "/app/alt-svc-h1" 200)"
  assert_response_jq "${h1}" '.headers["alt-svc"] == "h3=\":8443\"; ma=86400"'
  h2="$(protocol_probe_client "h2" "example.test" "/app/alt-svc-h2" 200)"
  assert_response_jq "${h2}" '.headers["alt-svc"] == "h3=\":8443\"; ma=86400"'
}
