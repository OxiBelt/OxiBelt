run_case_checks() {
  local downstream upstream next_protocol proxy_status first second path
  for downstream in h1 h2 h3; do
    for upstream in h1 h2 h3; do
      case "${upstream}" in
        h1) next_protocol="http/1.1" ;;
        h2) next_protocol="h2" ;;
        h3) next_protocol="h3" ;;
      esac
      proxy_status="\"status-test\"; received-status=200; next-protocol=${next_protocol}"
      incremental_probe_client \
        "${downstream}" \
        "/${upstream}/duplex" \
        200 \
        duplex \
        --expect-proxy-status "${proxy_status}" \
        --expect-cache-status "incremental; hit, \"status-test\"; fwd=method; fwd-status=200"
    done
  done

  for downstream in h1 h2 h3; do
    path="/cache/${downstream}?body=${downstream}&cache_control=public&content_type=text/plain"
    case "${downstream}" in
      h1)
        first="$(client_request "example.test" "${path}" 200)"
        second="$(client_request "example.test" "${path}" 200)"
        ;;
      h2 | h3)
        first="$(protocol_probe_client "${downstream}" "example.test" "${path}" 200)"
        second="$(protocol_probe_client "${downstream}" "example.test" "${path}" 200)"
        ;;
    esac
    assert_response_jq \
      "${first}" \
      '.headers["cache-status"] | test("^\\\"status-test\\\"; fwd=miss; fwd-status=200; stored$")'
    assert_response_jq \
      "${second}" \
      '.headers["cache-status"] | test("^\\\"status-test\\\"; hit; ttl=[0-9]+$")'
  done
}
