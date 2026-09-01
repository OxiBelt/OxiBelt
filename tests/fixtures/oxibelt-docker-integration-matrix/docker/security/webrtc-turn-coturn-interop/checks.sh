run_case_checks() {
  local output

  output="$(protocol_probe_turn_client udp 3478 valid allocate-success)"
  assert_response_jq "${output}" '.transport == "udp" and .expect == "allocate-success"'
  output="$(protocol_probe_turn_client udp 4478 valid allocate-success)"
  assert_response_jq "${output}" '.transport == "udp" and .expect == "allocate-success"'

  output="$(coturn_turn_client 3478 udp ipv4 udp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn UDP client returned no proxy-mode evidence"
  output="$(coturn_turn_client 3479 tcp ipv4 udp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn TCP client returned no proxy-mode evidence"
  output="$(coturn_turn_client 5349 tls ipv4 udp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn TLS client returned no proxy-mode evidence"

  output="$(coturn_turn_client 4478 udp ipv4 udp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn UDP client returned no edge IPv4 evidence"
  output="$(coturn_turn_client 4479 tcp ipv4 udp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn TCP client returned no edge IPv4 evidence"
  output="$(coturn_turn_client 6349 tls ipv4 udp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn TLS client returned no edge IPv4 evidence"
  output="$(coturn_turn_client 4478 udp ipv6 udp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn UDP client returned no edge IPv6 evidence"
  output="$(coturn_turn_client 4479 tcp ipv6 udp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn TCP client returned no edge IPv6 evidence"
  output="$(coturn_turn_client 6349 tls ipv6 udp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn TLS client returned no edge IPv6 evidence"

  output="$(coturn_turn_client 4479 tcp ipv4 tcp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn RFC 6062 client returned no IPv4 evidence"
  output="$(coturn_turn_client 4479 tcp ipv6 tcp)"
  [[ -n "${output}" ]] || fail_with_diagnostics "coturn RFC 6062 client returned no IPv6 evidence"
}
