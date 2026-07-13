assert_forward_auth_projection() {
  local response="$1"
  local protocol="$2"

  assert_response_jq "${response}" ".negotiated_protocol == \"${protocol}\""
  assert_body_jq "${response}" '.method == "GET"
    and .headers["x-forwarded-method"] == "GET"
    and .headers["x-forwarded-uri"] == "/admin?view=summary"
    and .headers["x-forwarded-host"] == "vault.example.test"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-route"] == "vault-admin"
    and .headers["x-original-url"] == "https://vault.example.test/admin?view=summary"'
}

run_case_checks() {
  local h2 h3

  h2="$(protocol_probe_client "h2" "vault.example.test" "/admin?view=summary" 418)"
  assert_forward_auth_projection "${h2}" "h2"

  h3="$(protocol_probe_client "h3" "vault.example.test" "/admin?view=summary" 418)"
  assert_forward_auth_projection "${h3}" "h3"
}
