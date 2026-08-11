
run_case_checks() {
  local local_tcp explicit_tcp default_tcp local_quic local_split_quic forwarded_quic forwarded_split_quic metrics

  local_tcp="$(client_request_with_sni "example.test" "example.test" "/app/sni-local-tcp" 200)"
  assert_body_jq "${local_tcp}" '.upstream == "http-upstream"
    and .scheme == "http"
    and .path == "/origin/app/sni-local-tcp"'

  explicit_tcp="$(sni_forward_tls_request "sni-forward.test" "/tcp-explicit?case=sni" 200)"
  assert_body_jq "${explicit_tcp}" '.upstream == "https-upstream"
    and .scheme == "https"
    and .path == "/tcp-explicit?case=sni"
    and .headers.host == "sni-forward.test"'

  default_tcp="$(sni_forward_tls_request "sni-default.test" "/tcp-default?case=sni" 200)"
  assert_body_jq "${default_tcp}" '.upstream == "https-upstream"
    and .scheme == "https"
    and .path == "/tcp-default?case=sni"
    and .headers.host == "sni-default.test"'

  local_quic="$(protocol_probe_client_with_sni_and_ca "h3" "example.test" "example.test" "/app/sni-local-h3" 200 "${cert_dir}/fullchain.pem")"
  assert_response_jq "${local_quic}" '.negotiated_protocol == "h3"'
  assert_body_jq "${local_quic}" '.upstream == "http-upstream"
    and .path == "/origin/app/sni-local-h3"'

  local_split_quic="$(protocol_probe_client_with_sni_and_ca "h3" "example.test" "example.test" "/app/sni-local-h3-split" 200 "${cert_dir}/fullchain.pem" --quic-initial-alpn-padding 4096)"
  assert_response_jq "${local_split_quic}" '.negotiated_protocol == "h3" and .quic_initial_udp_segments >= 2'
  assert_body_jq "${local_split_quic}" '.upstream == "http-upstream"
    and .path == "/origin/app/sni-local-h3-split"'

  forwarded_quic="$(protocol_probe_client_with_sni_and_ca "h3" "quic-forward.test" "quic-forward.test" "/quic-explicit?case=sni" 200 "${upstream_tls_dir}/ca.pem")"
  assert_response_jq "${forwarded_quic}" '.negotiated_protocol == "h3"'
  assert_body_jq "${forwarded_quic}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .path == "/quic-explicit?case=sni"'

  forwarded_split_quic="$(protocol_probe_client_with_sni_and_ca "h3" "quic-forward.test" "quic-forward.test" "/quic-explicit?case=sni-split" 200 "${upstream_tls_dir}/ca.pem" --quic-initial-alpn-padding 4096)"
  assert_response_jq "${forwarded_split_quic}" '.negotiated_protocol == "h3" and .quic_initial_udp_segments >= 2'
  assert_body_jq "${forwarded_split_quic}" '.upstream == "h3-upstream"
    and .scheme == "https"
    and .path == "/quic-explicit?case=sni-split"'

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_sni_forward_decisions_total")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_sni_forward_tcp_bytes_total")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_sni_forward_udp_bytes_total")'
  assert_response_jq "${metrics}" '[.body | split("\n")[] | select(startswith("oxibelt_sni_forward_quic_initial_reassembly_total{outcome=\"completed\"} ")) | split(" ") | last | tonumber] | any(. >= 4)'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"tcp_tls\",decision=\"forward\",rule=\"tcp-explicit\",target=\"mock-https:18443\"")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"tcp_tls\",decision=\"forward\",rule=\"default\",target=\"mock-https:18443\"")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"tcp_tls\",decision=\"local\",rule=\"local_route\",target=\"local\"")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"quic\",decision=\"forward\",rule=\"quic-explicit\",target=\"mock-h3:18445\"")'
  assert_response_jq "${metrics}" '.body | contains("protocol=\"quic\",decision=\"local\",rule=\"local_route\",target=\"local\"")'
}
