
run_case_checks() {
  local response
  local reloaded_response=""
  local attempt

  start_webtransport_reload_probe

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  for attempt in $(seq 1 30); do
    response="$(protocol_probe_client h3 "example.test" "/app/reloaded-check" 200)"
    if jq -e '.body | fromjson | .upstream == "alt-upstream"' <<<"${response}" >/dev/null; then
      reloaded_response="${response}"
      break
    fi
    sleep 1
  done
  if [[ -z "${reloaded_response}" ]]; then
    echo "${response}" >&2
    fail_with_diagnostics "new HTTP/3 connection did not observe the reloaded snapshot"
  fi
  assert_body_jq "${reloaded_response}" '.upstream == "alt-upstream" and .path == "/alt/app/reloaded-check"'

  docker exec "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" touch /tmp/resume
  wait_webtransport_reload_probe
  response="$(cat "${WEBTRANSPORT_RELOAD_PROBE_LOG}")"
  assert_response_jq "${response}" '.initial_webtransport_status == 200 and .drained_webtransport_status == 503 and .drained_http_status == 503'
}

start_webtransport_reload_probe() {
  WEBTRANSPORT_RELOAD_PROBE_CONTAINER="$(unique_docker_container_name "oxibelt-webtransport-reload-client")"
  WEBTRANSPORT_RELOAD_PROBE_LOG="${logs_dir}/${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}.log"
  docker create \
    --name "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" \
    --label "${test_label}" \
    --network "${network_name}" \
    "${protocol_probe_image}" \
    webtransport-reload-gated \
    --host proxy \
    --port 8443 \
    --server-name proxy \
    --authority example.test \
    --path /wt/session \
    --http-path /app/stale-after-reload \
    --ca-cert /tmp/proxy-ca.pem \
    --first-ready-path /tmp/first-ready \
    --resume-path /tmp/resume \
    --expect-initial-status 200 \
    --expect-drained-status 503 >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}:/tmp/proxy-ca.pem"
  docker start -a "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" >"${WEBTRANSPORT_RELOAD_PROBE_LOG}" 2>&1 &
  WEBTRANSPORT_RELOAD_PROBE_PID=$!

  for _attempt in $(seq 1 100); do
    if docker exec "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" test -f /tmp/first-ready >/dev/null 2>&1; then
      return
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" 2>/dev/null || true)" != "true" ]]; then
      cat "${WEBTRANSPORT_RELOAD_PROBE_LOG}" >&2 || true
      fail_with_diagnostics "WebTransport reload probe exited before first session was ready"
    fi
    sleep 0.2
  done

  cat "${WEBTRANSPORT_RELOAD_PROBE_LOG}" >&2 || true
  fail_with_diagnostics "WebTransport reload probe did not report first session readiness"
}

wait_webtransport_reload_probe() {
  if ! wait "${WEBTRANSPORT_RELOAD_PROBE_PID}"; then
    cat "${WEBTRANSPORT_RELOAD_PROBE_LOG}" >&2 || true
    fail_with_diagnostics "WebTransport reload probe failed"
  fi
  docker rm -f "${WEBTRANSPORT_RELOAD_PROBE_CONTAINER}" >/dev/null 2>&1 || true
}
