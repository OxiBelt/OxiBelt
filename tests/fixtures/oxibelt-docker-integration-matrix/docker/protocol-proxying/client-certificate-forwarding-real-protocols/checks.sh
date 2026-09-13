run_case_checks() {
  local urlpem second_urlpem rfc9440 response present_first present_hit second_first second_hit absent_first absent_hit websocket webtransport resumption
  urlpem="$( { printf '%s\n' '-----BEGIN CERTIFICATE-----'; openssl x509 -in "${client_tls_dir}/client.pem" -outform DER | base64 -w 64; printf '%s\n' '-----END CERTIFICATE-----'; } | jq -sRr @uri )"
  rfc9440=":$(openssl x509 -in "${client_tls_dir}/client.pem" -outform DER | base64 -w 0):"
  second_urlpem="$( { printf '%s\n' '-----BEGIN CERTIFICATE-----'; openssl x509 -in "${client_tls_dir}/client-second.pem" -outform DER | base64 -w 64; printf '%s\n' '-----END CERTIFICATE-----'; } | jq -sRr @uri )"

  assert_forwarded_header() {
    local candidate="$1"
    local expected="$2"
    if ! jq -e --arg expected "${expected}" '.body | fromjson | .headers["x-verified-client-cert"] == $expected' <<<"${candidate}" >/dev/null; then
      echo "upstream did not receive the exact verified client certificate leaf" >&2
      echo "${candidate}" >&2
      fail_with_diagnostics "client certificate forwarding value mismatch"
    fi
  }

  assert_h1_forwarded_header() {
    local candidate="$1"
    local expected="$2"
    if ! jq -e --arg expected "${expected}" '.response_base64 | @base64d | split("\r\n\r\n")[1] | fromjson | .headers["x-verified-client-cert"] == $expected' <<<"${candidate}" >/dev/null; then
      echo "HTTP/1 upstream did not receive the exact verified client certificate leaf" >&2
      echo "${candidate}" >&2
      fail_with_diagnostics "HTTP/1 client certificate forwarding value mismatch"
    fi
  }

  for protocol in h1 h2 h3; do
    local response_urlpem response_rfc9440
    if [[ "${protocol}" == "h1" ]]; then
      response_urlpem="$(protocol_probe_http1_client_with_client_identity "forward-h1-urlpem.example.test" "/certificate/${protocol}")"
      response_rfc9440="$(protocol_probe_http1_client_with_client_identity "forward-h1-rfc9440.example.test" "/certificate/${protocol}")"
    else
      response_urlpem="$(protocol_probe_client_with_client_identity "${protocol}" "forward-${protocol}-urlpem.example.test" "/certificate/${protocol}" 200)"
      response_rfc9440="$(protocol_probe_client_with_client_identity "${protocol}" "forward-${protocol}-rfc9440.example.test" "/certificate/${protocol}" 200)"
    fi
    if [[ "${protocol}" == "h1" ]]; then
      assert_h1_forwarded_header "${response_urlpem}" "${urlpem}"
      assert_h1_forwarded_header "${response_rfc9440}" "${rfc9440}"
    else
      assert_forwarded_header "${response_urlpem}" "${urlpem}"
      assert_forwarded_header "${response_rfc9440}" "${rfc9440}"
    fi
  done

  response="$(protocol_probe_client "h2" "forward-h2-urlpem.example.test" "/certificate/absent" 200)"
  assert_body_jq "${response}" '.headers["x-verified-client-cert"] == null'

  response="$(protocol_probe_client_with_explicit_identity h2 "forward-h2-urlpem.example.test" "/certificate/spoof" 200 "${client_tls_dir}/client.pem" "${client_tls_dir}/client.key" --header 'x-verified-client-cert: attacker-one' --header 'X-Verified-Client-Cert: attacker-two')"
  assert_forwarded_header "${response}" "${urlpem}"

  websocket="$(protocol_probe_websocket_client_with_client_identity "forward-ws.example.test" "/ws/forward" "verified-websocket")"
  assert_response_jq "${websocket}" '.status == 101 and .upgraded == true and .echoed_bytes == 18'
  webtransport="$(protocol_probe_webtransport_multiplex_with_client_identity "forward-wt.example.test" "/wt/forward")"
  assert_response_jq "${webtransport}" '.statuses == [200] and .stream_echo_bytes > 0 and .datagram_echo_bytes > 0'

  present_first="$(protocol_probe_client_with_explicit_identity h2 "forward-cache.example.test" "/certificate/cache?cache_control=public%2Cmax-age%3D60" 200 "${client_tls_dir}/client.pem" "${client_tls_dir}/client.key" --header 'accept-encoding: gzip')"
  present_hit="$(protocol_probe_client_with_explicit_identity h2 "forward-cache.example.test" "/certificate/cache?cache_control=public%2Cmax-age%3D60" 200 "${client_tls_dir}/client.pem" "${client_tls_dir}/client.key" --header 'accept-encoding: gzip')"
  second_first="$(protocol_probe_client_with_explicit_identity h2 "forward-cache.example.test" "/certificate/cache?cache_control=public%2Cmax-age%3D60" 200 "${client_tls_dir}/client-second.pem" "${client_tls_dir}/client-second.key")"
  second_hit="$(protocol_probe_client_with_explicit_identity h2 "forward-cache.example.test" "/certificate/cache?cache_control=public%2Cmax-age%3D60" 200 "${client_tls_dir}/client-second.pem" "${client_tls_dir}/client-second.key")"
  absent_first="$(protocol_probe_client h2 "forward-cache.example.test" "/certificate/cache?cache_control=public%2Cmax-age%3D60" 200)"
  absent_hit="$(protocol_probe_client h2 "forward-cache.example.test" "/certificate/cache?cache_control=public%2Cmax-age%3D60" 200)"
  assert_response_jq "${present_first}" '.headers["cache-control"] == "no-store" and .headers["x-oxibelt-cache"] == "miss"'
  assert_body_jq "${present_first}" '.headers["accept-encoding"] == null'
  assert_response_jq "${present_hit}" '.headers["cache-control"] == "no-store" and .headers["x-oxibelt-cache"] == "hit"'
  assert_response_jq "${second_first}" '.headers["cache-control"] == "no-store" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${second_hit}" '.headers["cache-control"] == "no-store" and .headers["x-oxibelt-cache"] == "hit"'
  assert_response_jq "${absent_first}" '.headers["cache-control"] == "no-store" and .headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${absent_hit}" '.headers["cache-control"] == "no-store" and .headers["x-oxibelt-cache"] == "hit"'
  assert_forwarded_header "${present_first}" "${urlpem}"
  assert_forwarded_header "${present_hit}" "${urlpem}"
  assert_forwarded_header "${second_first}" "${second_urlpem}"
  assert_forwarded_header "${second_hit}" "${second_urlpem}"
  assert_body_jq "${absent_first}" '.headers["x-verified-client-cert"] == null'
  assert_body_jq "${absent_hit}" '.headers["x-verified-client-cert"] == null'

  resumption="$(protocol_probe_tls_resumption_load_with_client_identity "forward-h1-urlpem.example.test" "/certificate/resumption" 4 1 "x-verified-client-cert:${urlpem}")"
  assert_response_jq "${resumption}" '.connections == 4 and .full >= 1 and .resumed >= 1'
}
