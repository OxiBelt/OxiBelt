run_case_checks() {
  local downstream upstream expected response payload
  for downstream in h1 h2 h3; do
    if [[ "${downstream}" == "h1" ]]; then
      expected=101
    else
      expected=200
    fi
    for upstream in h1 h2 h3; do
      payload="ws-${downstream}-to-${upstream}"
      response="$(protocol_probe_websocket_client "ws-${upstream}.example.test" "/ws/echo" "${expected}" "${payload}" "${downstream}")"
      assert_response_jq "${response}" ".status == ${expected} and .upgraded == true and .echoed_bytes == ${#payload}"
      if [[ "${downstream}" != "h1" ]]; then
        assert_response_jq "${response}" ".protocol == \"${downstream}\" and .ping_pong == true and .closed == true"
      fi
    done

    payload="ws-${downstream}-to-h2c"
    response="$(protocol_probe_websocket_client "ws-h2c.example.test" "/ws/echo" "${expected}" "${payload}" "${downstream}")"
    assert_response_jq "${response}" ".status == ${expected} and .upgraded == true and .echoed_bytes == ${#payload}"

    response="$(protocol_probe_websocket_client "ws-disabled.example.test" "/ws/echo" 502 "blocked" "${downstream}")"
    assert_response_jq "${response}" '.status == 502 and .upgraded == false'

    response="$(protocol_probe_websocket_client "ws-h1.example.test" "/ws/blocked" 403 "blocked" "${downstream}")"
    assert_response_jq "${response}" '.status == 403 and .upgraded == false'
  done

  response="$(protocol_probe_websocket_client "ws-h1.example.test" "/ws/echo" 200 "h2-sibling" h2 true)"
  assert_response_jq "${response}" '.protocol == "h2" and .unsupported_connect_status >= 400 and .ping_pong == true and .closed == true'

  response="$(protocol_probe_websocket_client "ws-h1.example.test" "/ws/echo" 200 "h3-sibling" h3 true)"
  assert_response_jq "${response}" '.protocol == "h3" and .unsupported_connect_status == 501 and .ping_pong == true and .closed == true'
}
