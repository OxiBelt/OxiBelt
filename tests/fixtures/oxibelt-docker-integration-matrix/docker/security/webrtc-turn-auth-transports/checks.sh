
run_case_checks() {
  local udp tcp tls
  udp="$(protocol_probe_turn_client udp 3478 valid echo)"
  assert_response_jq "${udp}" '.transport == "udp" and .expect == "echo"'
  tcp="$(protocol_probe_turn_client tcp 3479 valid echo)"
  assert_response_jq "${tcp}" '.transport == "tcp" and .expect == "echo"'
  tls="$(protocol_probe_turn_client tls 5349 valid echo)"
  assert_response_jq "${tls}" '.transport == "tls" and .expect == "echo"'

  udp="$(protocol_probe_turn_client udp 3478 invalid no-response)"
  assert_response_jq "${udp}" '.transport == "udp" and .expect == "no-response"'
  tcp="$(protocol_probe_turn_client tcp 3479 invalid no-response)"
  assert_response_jq "${tcp}" '.transport == "tcp" and .expect == "no-response"'
  tls="$(protocol_probe_turn_client tls 5349 invalid no-response)"
  assert_response_jq "${tls}" '.transport == "tls" and .expect == "no-response"'
}
