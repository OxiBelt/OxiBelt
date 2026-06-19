
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/admin-rebind-before?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/admin-rebind-before?cache_control=public" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body == "purged=1\n"'

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  response="$(client_request "example.test" "/app/admin-rebind-after?cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'

  response="$(plain_client_request_with_headers_on_port 9093 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/admin-rebind-after?cache_control=public" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body == "purged=1\n"'

  assert_old_admin_port_closed
}

assert_old_admin_port_closed() {
  local output=""
  local client_container="oxibelt-old-admin-client-${run_id}-${RANDOM}"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --scheme http \
    --path "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/admin-rebind-after?cache_control=public" \
    --host "proxy" \
    --port 9092 \
    --method POST \
    --body "" \
    --dump-response-json \
    --expect-status 200 \
    --header "Authorization: Bearer matrix-admin-token" >/dev/null

  if output="$(docker start -a "${client_container}" 2>&1)"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    echo "${output}" >&2
    fail_with_diagnostics "old admin listener stayed reachable after rebind"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
}
