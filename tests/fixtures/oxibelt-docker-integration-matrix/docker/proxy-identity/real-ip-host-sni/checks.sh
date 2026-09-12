real_ip_sni_request() {
  local server_name="$1"
  local host="$2"
  local path="$3"
  local expected_status="$4"
  local forwarded_client_ip="${5:-203.0.113.10}"
  local client_container output status=0

  for attempt in $(seq 1 30); do
    client_container="$(unique_docker_container_name "oxibelt-real-ip-sni-client" "${attempt}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      --entrypoint python \
      "${mock_image}" \
      /opt/mock_upstream/client.py \
      --target-host proxy \
      --server-name "${server_name}" \
      --path "${path}" \
      --host "${host}" \
      --port 8443 \
      --method GET \
      --body "" \
      --header "X-Forwarded-For: ${forwarded_client_ip}" \
      --ca-file /tmp/proxy-ca.pem \
      --dump-response-json \
      --expect-status "${expected_status}" >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"

    if output="$(docker_start_stdout_only "${client_container}")"; then
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      printf '%s' "${output}"
      return 0
    fi
    status=$?
    append_container_stderr "${client_container}"
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    sleep 1
  done

  echo "Real-IP SNI client request for ${server_name} failed after retries with status ${status}" >&2
  echo "${output}" >&2
  fail_with_diagnostics "Real-IP SNI client request did not reach expected status ${expected_status}"
}

run_case_checks() {
  local response

  response="$(real_ip_sni_request "proxy" "host.identity.test" "/identity/host" 451)"
  assert_response_jq "${response}" '.body == "selected forwarded identity blocked"'

  response="$(real_ip_sni_request "proxy" "host.identity.test" "/identity/host-safe" 200 "198.51.100.10")"
  assert_body_jq "${response}" '.path == "/origin/identity/host-safe" and .headers["x-forwarded-for"] == "198.51.100.10"'

  response="$(real_ip_sni_request "example.test" "fallback.identity.test" "/identity/sni" 451)"
  assert_response_jq "${response}" '.body == "selected forwarded identity blocked"'

  response="$(real_ip_sni_request "example.test" "combined.identity.test" "/identity/combined" 451)"
  assert_response_jq "${response}" '.body == "selected forwarded identity blocked"'

  response="$(real_ip_sni_request "proxy" "combined.identity.test" "/identity/mismatched-sni" 200)"
  assert_body_jq "${response}" '.path == "/origin/identity/mismatched-sni"'

  response="$(real_ip_sni_request "example.test" "disabled.identity.test" "/identity/disabled" 200)"
  assert_body_jq "${response}" '.path == "/origin/identity/disabled"'

  response="$(real_ip_sni_request "proxy" "fallback.identity.test" "/identity/fallback" 200)"
  assert_body_jq "${response}" '.path == "/origin/identity/fallback"'
}
