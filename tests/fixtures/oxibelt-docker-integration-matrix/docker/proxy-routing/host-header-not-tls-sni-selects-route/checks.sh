
run_case_checks() {
  local response
  response="$(client_request_with_sni "proxy" "api.example.test" "/sni/host-route" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/sni/host-route"'
}
