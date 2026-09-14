run_case_checks() {
  local rfc9440 first first_hit second second_hit h1 h2 h3 h3_second_identity h3_first_connection_id h3_second_connection_id websocket webtransport resumption
  rfc9440=":$(openssl x509 -in "${client_tls_dir}/client.pem" -outform DER | base64 -w 0):"
  second_rfc9440=":$(openssl x509 -in "${client_tls_dir}/client-second.pem" -outform DER | base64 -w 0):"

  assert_header() {
    local candidate="$1" expected="$2"
    if ! jq -e --arg expected "${expected}" \
      '.body | fromjson | .headers["client-cert"] == $expected and .headers["client_cert"] == null' \
      <<<"${candidate}" >/dev/null; then
      echo "upstream did not receive the exact RFC 9440 Client-Cert leaf" >&2
      echo "${candidate}" >&2
      fail_with_diagnostics "RFC 9440 Client-Cert forwarding mismatch"
    fi
  }

  assert_h1_header() {
    local candidate="$1" expected="$2"
    if ! jq -e --arg expected "${expected}" \
      '.response_base64 | @base64d | split("\r\n\r\n")[1] | fromjson | .headers["client-cert"] == $expected and .headers["client_cert"] == null' \
      <<<"${candidate}" >/dev/null; then
      echo "HTTP/1 upstream did not receive the exact RFC 9440 Client-Cert leaf" >&2
      echo "${candidate}" >&2
      fail_with_diagnostics "HTTP/1 RFC 9440 Client-Cert forwarding mismatch"
    fi
  }

  h1="$(protocol_probe_http1_client_with_client_identity "identity-h1.example.test" "/h1" 'Client-Cert: attacker-one' 'client_cert: attacker-alias')"
  h2="$(protocol_probe_client_with_client_identity h2 "identity-h2.example.test" "/h2" 200 --header 'client-cert: attacker-one' --header 'Client-Cert: attacker-two' --header 'client_cert: attacker-alias')"
  h3="$(protocol_probe_client_with_client_identity h3 "identity-h3.example.test" "/h3" 200 --header 'client-cert: attacker-one' --header 'Client-Cert: attacker-two' --header 'client_cert: attacker-alias')"
  assert_h1_header "${h1}" "${rfc9440}"
  assert_header "${h2}" "${rfc9440}"
  assert_header "${h3}" "${rfc9440}"
  h3_second_identity="$(protocol_probe_client_with_explicit_identity h3 "identity-h3.example.test" "/h3-second-identity" 200 "${client_tls_dir}/client-second.pem" "${client_tls_dir}/client-second.key")"
  assert_header "${h3_second_identity}" "${second_rfc9440}"
  h3_first_connection_id="$(jq -er '.body | fromjson | .connection_id | numbers' <<<"${h3}")"
  h3_second_connection_id="$(jq -er '.body | fromjson | .connection_id | numbers' <<<"${h3_second_identity}")"
  if [[ "${h3_first_connection_id}" != "${h3_second_connection_id}" ]]; then
    fail_with_diagnostics "upstream H3 pool did not reuse its connection across downstream identities"
  fi

  assert_upstream_tls_rejection() {
    local authority="$1" evidence="$2" response proxy_logs
    response="$(protocol_probe_client_with_client_identity h2 "${authority}" "/upstream-tls-rejection" 502)"
    assert_response_jq "${response}" '.status == 502'
    proxy_logs="$(docker logs "${proxy_container}" 2>&1 || true)"
    if ! grep -Eqi "${evidence}" <<<"${proxy_logs}"; then
      echo "${proxy_logs}" >&2
      fail_with_diagnostics "upstream TLS rejection lacked the expected certificate-validation evidence"
    fi
  }
  assert_upstream_tls_rejection "identity-name-mismatch.example.test" 'notvalidforname|not valid for name|certificate.*name'
  assert_upstream_tls_rejection "identity-system-trust.example.test" 'unknownissuer|unknown issuer'

  websocket="$(protocol_probe_websocket_client_with_client_identity "identity-ws.example.test" "/ws" "verified-websocket" --header 'client_cert: attacker')"
  assert_response_jq "${websocket}" '.status == 101 and .upgraded == true and .echoed_bytes == 18'
  webtransport="$(protocol_probe_webtransport_multiplex_with_client_identity "identity-wt.example.test" "/wt" --header 'client_cert: attacker')"
  assert_response_jq "${webtransport}" '.statuses == [200] and .stream_echo_bytes > 0 and .datagram_echo_bytes > 0'

  assert_downstream_mtls_rejects() {
    local identity="$1" client_container output errors request_base64
    request_base64="$(printf 'GET /downstream-mtls-negative HTTP/1.1\r\nHost: identity-h1.example.test\r\nConnection: close\r\n\r\n' | base64 -w 0)"
    client_container="$(unique_docker_container_name "oxibelt-downstream-mtls-negative" "${identity}")"
    docker create --name "${client_container}" --label "${test_label}" --network "${network_name}" \
      "${protocol_probe_image}" raw-tls-http --host proxy --port 8443 --server-name proxy \
      --ca-cert /tmp/proxy-ca.pem --request-base64 "${request_base64}" \
      ${identity:+--client-cert /tmp/client.pem --client-key /tmp/client.key} >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"
    if [[ -n "${identity}" ]]; then
      docker cp "${postgres_tls_dir}/client.pem" "${client_container}:/tmp/client.pem"
      docker cp "${postgres_tls_dir}/client.key" "${client_container}:/tmp/client.key"
    fi
    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      echo "${output}" >&2
      fail_with_diagnostics "required downstream mTLS accepted ${identity:-missing} certificate"
    fi
    errors="$(cat "$(container_stderr_log "${client_container}")" 2>/dev/null || true; docker logs "${client_container}" 2>&1 || true)"
    if ! grep -Eqi 'certificate.?required|unknown.?ca|unknownissuer|bad.?certificate|invalid.?certificate' <<<"${errors}"; then
      echo "${errors}" >&2
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      fail_with_diagnostics "downstream negative probe failed without certificate-related TLS evidence"
    fi
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
  }
  assert_downstream_mtls_rejects ""
  assert_downstream_mtls_rejects "untrusted"

  first="$(protocol_probe_client_with_explicit_identity h2 "identity-cache.example.test" "/cache?cache_control=public%2Cmax-age%3D60" 200 "${client_tls_dir}/client.pem" "${client_tls_dir}/client.key")"
  first_hit="$(protocol_probe_client_with_explicit_identity h2 "identity-cache.example.test" "/cache?cache_control=public%2Cmax-age%3D60" 200 "${client_tls_dir}/client.pem" "${client_tls_dir}/client.key")"
  second="$(protocol_probe_client_with_explicit_identity h2 "identity-cache.example.test" "/cache?cache_control=public%2Cmax-age%3D60" 200 "${client_tls_dir}/client-second.pem" "${client_tls_dir}/client-second.key")"
  second_hit="$(protocol_probe_client_with_explicit_identity h2 "identity-cache.example.test" "/cache?cache_control=public%2Cmax-age%3D60" 200 "${client_tls_dir}/client-second.pem" "${client_tls_dir}/client-second.key")"
  assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss" and .headers["cache-control"] == "no-store"'
  assert_response_jq "${first_hit}" '.headers["x-oxibelt-cache"] == "hit"'
  assert_response_jq "${second}" '.headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${second_hit}" '.headers["x-oxibelt-cache"] == "hit"'
  assert_header "${first}" "${rfc9440}"
  assert_header "${first_hit}" "${rfc9440}"
  assert_header "${second}" "${second_rfc9440}"
  assert_header "${second_hit}" "${second_rfc9440}"

  resumption="$(protocol_probe_tls_resumption_load_with_client_identity "identity-h1.example.test" "/resumption" 4 1 "client-cert:${rfc9440}")"
  assert_response_jq "${resumption}" '.connections == 4 and .full >= 1 and .resumed >= 1'

  assert_upstream_mtls_rejects() {
    local identity="$1" client_container request_base64 output errors
    request_base64="$(printf 'GET /origin HTTP/1.1\r\nHost: mock-https\r\nConnection: close\r\n\r\n' | base64 -w 0)"
    client_container="$(unique_docker_container_name "oxibelt-upstream-mtls-negative" "${identity}")"
    docker create --name "${client_container}" --label "${test_label}" --network "${network_name}" \
      "${protocol_probe_image}" raw-tls-http --host mock-https --port 18443 --server-name mock-https \
      --ca-cert /tmp/upstream-ca.pem --request-base64 "${request_base64}" \
      ${identity:+--client-cert /tmp/client.pem --client-key /tmp/client.key} >/dev/null
    docker cp "${upstream_tls_dir}/ca.pem" "${client_container}:/tmp/upstream-ca.pem"
    if [[ -n "${identity}" ]]; then
      docker cp "${client_tls_dir}/client.pem" "${client_container}:/tmp/client.pem"
      docker cp "${client_tls_dir}/client.key" "${client_container}:/tmp/client.key"
    fi
    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      echo "${output}" >&2
      fail_with_diagnostics "upstream mTLS accepted ${identity:-missing} client certificate"
    fi
    errors="$(cat "$(container_stderr_log "${client_container}")" 2>/dev/null || true; docker logs "${client_container}" 2>&1 || true)"
    if ! grep -Eqi 'certificate.?required|unknown.?ca|unknownissuer|bad.?certificate|invalid.?certificate' <<<"${errors}"; then
      echo "${errors}" >&2
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      fail_with_diagnostics "upstream negative probe failed without certificate-related TLS evidence"
    fi
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
  }
  assert_upstream_mtls_rejects ""
  assert_upstream_mtls_rejects "wrong"
}
