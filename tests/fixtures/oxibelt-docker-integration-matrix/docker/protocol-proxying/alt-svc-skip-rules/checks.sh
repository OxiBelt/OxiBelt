
run_case_checks() {
  local plain h3 upgrade
  plain="$(plain_client_request "example.test" "/app/plain-alt-svc-skip" 200)"
  assert_response_jq "${plain}" '.headers["alt-svc"] == null'

  h3="$(protocol_probe_client "h3" "example.test" "/app/h3-alt-svc-skip" 200)"
  assert_response_jq "${h3}" '.headers["alt-svc"] == null'

  upgrade="$(upgrade_client_request "example.test" "/app/upgrade-alt-svc-skip" "matrix-upgrade" "hello-upgrade" 101)"
  assert_response_jq "${upgrade}" '.headers["alt-svc"] == null'
}
