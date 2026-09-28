run_case_checks() {
  local response="" logs="" baseline_failures=0 failures=0 attempt=0

  response="$(protocol_probe_client h3 "example.test" "/locales/en/messages.json" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3"'
  assert_body_jq "${response}" '.path == "/origin/locales/en/messages.json"'

  # The HTTP/3 path validator rejects dot segments before WAF evaluation.
  response="$(protocol_probe_client h3 "example.test" "/safe/../x" 400)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3" and .body == "invalid request path"'

  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  baseline_failures="$(grep -F -c 'hot reload failed; keeping previous active state' <<<"${logs}" || true)"
  docker cp "${case_dir}/config/invalid-oxibelt.toml" \
    "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  for ((attempt = 1; attempt <= 30; attempt++)); do
    logs="$(docker logs "${proxy_container}" 2>&1 || true)"
    failures="$(grep -F -c 'hot reload failed; keeping previous active state' <<<"${logs}" || true)"
    if ((failures > baseline_failures)); then
      break
    fi
    sleep 0.5
  done
  if ((failures <= baseline_failures)); then
    echo "${logs}" >&2
    fail_with_diagnostics "invalid OxiRule escape did not fail hot reload"
  fi
  if ! grep -F 'failed to parse WAF rule block-traversal expression' <<<"${logs}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "hot reload did not report the invalid OxiRule expression"
  fi

  response="$(protocol_probe_client h3 "example.test" "/locales/en/messages.json" 200)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3"'
  assert_body_jq "${response}" '.path == "/origin/locales/en/messages.json"'

  response="$(protocol_probe_client h3 "example.test" "/safe/../x" 400)"
  assert_response_jq "${response}" '.negotiated_protocol == "h3" and .body == "invalid request path"'
}
