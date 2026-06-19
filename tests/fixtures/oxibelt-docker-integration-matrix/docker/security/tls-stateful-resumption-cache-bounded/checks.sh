
run_case_checks() {
  local connections min_resumed first second final
  connections="${OXIBELT_TLS_RESUMPTION_LOAD_CONNECTIONS:-64}"
  min_resumed="${OXIBELT_TLS_RESUMPTION_MIN_RESUMED:-32}"

  first="$(protocol_probe_tls_resumption_load "example.test" "/app/tls-resumption?body=first" "${connections}" "${min_resumed}")"
  assert_response_jq "${first}" ".connections == ${connections}
    and .resumed >= ${min_resumed}
    and .full >= 1
    and .tickets_received >= ${min_resumed}"

  second="$(protocol_probe_tls_resumption_load "example.test" "/app/tls-resumption?body=second" "${connections}" "${min_resumed}")"
  assert_response_jq "${second}" ".connections == ${connections}
    and .resumed >= ${min_resumed}
    and .full >= 1
    and .tickets_received >= ${min_resumed}"

  final="$(client_request "example.test" "/app/tls-resumption-final?body=alive" 200)"
  assert_response_jq "${final}" '.body == "alive"'
}
