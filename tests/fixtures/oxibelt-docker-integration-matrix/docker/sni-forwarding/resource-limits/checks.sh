
quic_active_session_count() {
  local metrics="$1"
  jq -r '.body' <<<"${metrics}" | awk '$1 == "oxibelt_sni_forward_active_quic_sessions" { print int($2); found=1 } END { if (!found) print "-1" }'
}

start_partial_sni_client() {
  local client_container
  client_container="$(unique_docker_container_name "oxibelt-partial-sni-client")"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    -c 'import socket, time; sock = socket.create_connection(("proxy", 8443), timeout=3); sock.sendall(bytes([0x16, 0x03, 0x01, 0xff, 0xff])); time.sleep(2); sock.close()' >/dev/null
  docker start "${client_container}" >/dev/null
  printf '%s' "${client_container}"
}

run_case_checks() {
  local partial_client local_tcp explicit_tcp local_quic forwarded_quic metrics active

  partial_client="$(start_partial_sni_client)"
  sleep 1

  local_tcp="$(client_request_with_sni "example.test" "example.test" "/app/resource-local-tcp" 200)"
  assert_body_jq "${local_tcp}" '.upstream == "http-upstream"
    and .scheme == "http"
    and .path == "/origin/app/resource-local-tcp"'

  explicit_tcp="$(sni_forward_tls_request "sni-forward.test" "/resource-tcp?case=limits" 200)"
  assert_body_jq "${explicit_tcp}" '.upstream == "https-upstream"
    and .scheme == "https"
    and .path == "/resource-tcp?case=limits"
    and .headers.host == "sni-forward.test"'

  local_quic="$(protocol_probe_client_with_sni_and_ca "h3" "example.test" "example.test" "/app/resource-local-h3" 200 "${cert_dir}/fullchain.pem")"
  assert_response_jq "${local_quic}" '.negotiated_protocol == "h3"'
  assert_body_jq "${local_quic}" '.upstream == "http-upstream"
    and .path == "/origin/app/resource-local-h3"'

  for attempt in one two three four; do
    forwarded_quic="$(protocol_probe_client_with_sni_and_ca "h3" "quic-forward.test" "quic-forward.test" "/resource-quic-${attempt}?case=limits" 200 "${upstream_tls_dir}/ca.pem")"
    assert_response_jq "${forwarded_quic}" '.negotiated_protocol == "h3"'
    assert_body_jq "${forwarded_quic}" '.upstream == "h3-upstream"
      and .scheme == "https"
      and .path == "/resource-quic-'"${attempt}"'?case=limits"'
  done

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  active="$(quic_active_session_count "${metrics}")"
  if [[ "${active}" -lt 0 || "${active}" -gt 2 ]]; then
    echo "unexpected active QUIC SNI forwarding sessions: ${active}" >&2
    fail_with_diagnostics "SNI forwarding QUIC sessions exceeded configured resource limit"
  fi

  docker rm -f "${partial_client}" >/dev/null 2>&1 || true
}
      