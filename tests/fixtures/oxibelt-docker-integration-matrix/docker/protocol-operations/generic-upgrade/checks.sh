
run_case_checks() {
  local response
  response="$(upgrade_client_request "example.test" "/app/generic-upgrade" "matrix-upgrade" "hello-upgrade" 101)"
  assert_response_jq "${response}" '.body == "upgraded:hello-upgrade"'
  assert_response_jq "${response}" '.headers.upgrade == "matrix-upgrade"'
}
