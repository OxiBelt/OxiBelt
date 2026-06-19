
run_case_checks() {
  local response reloaded_response attempt

  response="$(client_request "example.test" "/app/telemetry-before" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/telemetry-before"'
  assert_body_jq "${response}" '.headers.traceparent | test("^00-[0-9a-f]{32}-[0-9a-f]{16}-01$")'

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  reloaded_response=""
  for attempt in $(seq 1 30); do
    response="$(client_request "example.test" "/app/telemetry-after" 200)"
    if jq -e '.body | fromjson | .path == "/reloaded/app/telemetry-after"' <<<"${response}" >/dev/null; then
      reloaded_response="${response}"
      break
    fi
    sleep 1
  done
  if [[ -z "${reloaded_response}" ]]; then
    echo "${response}" >&2
    fail_with_diagnostics "new HTTPS request did not observe the reloaded telemetry-disabled snapshot"
  fi

  assert_body_jq "${reloaded_response}" '.headers.traceparent == null'
}
