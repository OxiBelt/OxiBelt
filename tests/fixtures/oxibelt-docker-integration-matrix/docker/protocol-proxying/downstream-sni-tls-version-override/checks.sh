run_case_checks() {
  local legacy default
  legacy="$(protocol_probe_client_with_sni_and_ca "h2" "proxy-b" "proxy-b" "/legacy/tls12" 200 "${cert_dir}/fullchain.pem" --tls-version "tls1.2")"
  assert_response_jq "${legacy}" '.negotiated_protocol == "h2" and .tls_version == "tls1.2"'
  assert_body_jq "${legacy}" '.upstream == "http-upstream"
    and .path == "/origin/legacy/tls12"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "proxy-b"'

  default="$(protocol_probe_client_with_sni_and_ca "h2" "example.test" "example.test" "/default/tls13" 200 "${cert_dir}/fullchain.pem" --tls-version "tls1.3")"
  assert_response_jq "${default}" '.negotiated_protocol == "h2" and .tls_version == "tls1.3"'
  assert_body_jq "${default}" '.upstream == "http-upstream"
    and .path == "/origin/default/tls13"
    and .headers["x-forwarded-proto"] == "https"
    and .headers["x-forwarded-host"] == "example.test"'
}
