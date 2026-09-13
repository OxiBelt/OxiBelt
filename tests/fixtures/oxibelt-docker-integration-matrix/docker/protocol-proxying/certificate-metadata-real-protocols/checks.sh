run_case_checks() {
  local h1 h2 h3 h3_incomplete websocket webtransport

  h1="$(protocol_probe_http1_client_with_client_identity "certificate-h1.example.test" "/certificate/http1")"
  if ! jq -r '.response_base64' <<<"${h1}" | base64 -d | grep -Fq 'x-waf-certificate-response: matched'; then
    echo "HTTP/1 client-certificate response did not prove certificate metadata" >&2
    echo "${h1}" >&2
    fail_with_diagnostics "HTTP/1 certificate metadata rule did not match"
  fi
  if ! jq -e '.response_base64 | @base64d | split("\r\n\r\n")[1] | fromjson | .upstream == "https-upstream" and .request_version == "HTTP/1.1"' <<<"${h1}" >/dev/null; then
    echo "HTTP/1 request did not reach the HTTPS HTTP/1.1 upstream" >&2
    echo "${h1}" >&2
    fail_with_diagnostics "HTTP/1 certificate route selected an unexpected upstream"
  fi

  h2="$(protocol_probe_client_with_client_identity h2 "certificate-h2.example.test" "/certificate/http2" 200)"
  assert_response_jq "${h2}" '.negotiated_protocol == "h2" and .headers["x-waf-certificate-response"] == "matched"'
  assert_body_jq "${h2}" '.upstream == "h2-upstream" and .request_version == "HTTP/2.0"'

  h3="$(protocol_probe_client_with_client_identity h3 "certificate-h3.example.test" "/certificate/http3" 200)"
  assert_response_jq "${h3}" '.negotiated_protocol == "h3" and .headers["x-waf-certificate-response"] == "matched"'
  assert_body_jq "${h3}" '.upstream == "h3-upstream" and .request_version == "HTTP/3.0"'

  h3_incomplete="$(protocol_probe_client_with_explicit_identity \
    h3 \
    "certificate-h3.example.test" \
    "/certificate/incomplete-client-certificate" \
    404 \
    "${client_tls_dir}/client-too-many-names.pem" \
    "${client_tls_dir}/client-too-many-names.key")"
  assert_response_jq "${h3_incomplete}" '.negotiated_protocol == "h3" and .status == 404'

  websocket="$(protocol_probe_websocket_client_with_client_identity "certificate-ws.example.test" "/ws/certificate" "certificate-websocket")"
  assert_response_jq "${websocket}" '.status == 101 and .upgraded == true and .echoed_bytes == 21'

  webtransport="$(protocol_probe_webtransport_multiplex_with_client_identity "certificate-wt.example.test" "/wt/certificate")"
  assert_response_jq "${webtransport}" '.statuses == [200] and .stream_echo_bytes > 0 and .datagram_echo_bytes > 0'
}
