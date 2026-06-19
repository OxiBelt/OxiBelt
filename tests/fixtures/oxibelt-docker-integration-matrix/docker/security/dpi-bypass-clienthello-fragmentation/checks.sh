
run_case_checks() {
  local profile terminated forwarded
  local profiles=(
    byedpi-split-sni
    byedpi-tlsrec-sni
    goodbyedpi-native-frag
    goodbyedpi-frag-by-sni
    dpibreak-segment-0-1
    dpibreak-segment-0-5
  )

  for profile in "${profiles[@]}"; do
    terminated="$(protocol_probe_dpi_tls_client_with_sni_and_ca "${profile}" "example.test" "example.test" "/dpi/${profile}" 200 "${cert_dir}/fullchain.pem")"
    assert_response_jq "${terminated}" '.negotiated_protocol == "http/1.1"
      and .profile == "'"${profile}"'"
      and .client_hello_bytes > 0
      and .tcp_chunks >= 1
      and .tls_records >= 1'
    assert_body_jq "${terminated}" '.upstream == "http-upstream"
      and .path == "/origin/dpi/'"${profile}"'"
      and .headers["x-forwarded-proto"] == "https"
      and .headers["x-forwarded-host"] == "example.test"'

    forwarded="$(protocol_probe_dpi_tls_client_with_sni_and_ca "${profile}" "sni-forward.test" "sni-forward.test" "/dpi-sni/${profile}" 200 "${upstream_tls_dir}/ca.pem")"
    assert_response_jq "${forwarded}" '.negotiated_protocol == "http/1.1"
      and .profile == "'"${profile}"'"
      and .client_hello_bytes > 0
      and .tcp_chunks >= 1
      and .tls_records >= 1'
    assert_body_jq "${forwarded}" '.upstream == "https-upstream"
      and .scheme == "https"
      and .path == "/dpi-sni/'"${profile}"'"
      and .headers.host == "sni-forward.test"'
  done
}
