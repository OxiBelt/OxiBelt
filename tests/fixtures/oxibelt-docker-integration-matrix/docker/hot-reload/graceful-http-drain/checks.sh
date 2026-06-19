
run_case_checks() {
  local response h1_output h2_output

  start_holding_client_request_with_headers \
    "proxy" \
    8443 \
    "https" \
    "" \
    "example.test" \
    "/app/h1-drain?body=slow-h1&body_delay_ms=4500" \
    200 \
    0
  start_holding_h2_probe "/app/h2-drain?body=slow-h2&body_delay_ms=4500"

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  response="$(client_request_on_port 9443 "example.test" "/app/after-reload" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/app/after-reload"'

  wait_holding_h2_probe
  h2_output="$(cat "${H2_HOLD_LOG}")"
  assert_response_jq "${h2_output}" '.negotiated_protocol == "h2" and .status == 200 and .body == "slow-h2"'

  wait_holding_client
  h1_output="$(cat "${HOLDING_CLIENT_LOG}")"
  assert_response_jq "${h1_output}" '.status == 200 and .body == "slow-h1"'
}

start_holding_h2_probe() {
  local path="$1"
  H2_HOLD_CONTAINER="oxibelt-holding-h2-client-${run_id}-${RANDOM}"
  H2_HOLD_LOG="${logs_dir}/${H2_HOLD_CONTAINER}.log"
  docker create \
    --name "${H2_HOLD_CONTAINER}" \
    --label "${test_label}" \
    --network "${network_name}" \
    "${protocol_probe_image}" \
    downstream \
    --protocol h2 \
    --host proxy \
    --port 8443 \
    --server-name proxy \
    --authority example.test \
    --path "${path}" \
    --ca-cert /tmp/proxy-ca.pem \
    --expect-status 200 >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${H2_HOLD_CONTAINER}:/tmp/proxy-ca.pem"
  docker start -a "${H2_HOLD_CONTAINER}" >"${H2_HOLD_LOG}" 2>&1 &
  H2_HOLD_PID=$!
  sleep 1
}

wait_holding_h2_probe() {
  if ! wait "${H2_HOLD_PID}"; then
    cat "${H2_HOLD_LOG}" >&2 || true
    fail_with_diagnostics "holding HTTP/2 protocol probe failed"
  fi
  docker rm -f "${H2_HOLD_CONTAINER}" >/dev/null 2>&1 || true
}
