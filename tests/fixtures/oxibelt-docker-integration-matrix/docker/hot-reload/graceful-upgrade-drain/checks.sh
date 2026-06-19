
run_case_checks() {
  local response upgrade_output

  start_holding_upgrade_client_request_with_headers \
    "example.test" \
    "/app/upgrade-drain" \
    "matrixproto" \
    "drain-body" \
    101 \
    1500

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  response="$(client_request_on_port 9443 "example.test" "/app/after-upgrade-reload" 200)"
  assert_body_jq "${response}" '.upstream == "alt-upstream" and .path == "/alt/app/after-upgrade-reload"'

  wait_holding_client
  upgrade_output="$(cat "${HOLDING_CLIENT_LOG}")"
  assert_response_jq "${upgrade_output}" '.status == 101 and .body == "upgraded:drain-body"'
}
