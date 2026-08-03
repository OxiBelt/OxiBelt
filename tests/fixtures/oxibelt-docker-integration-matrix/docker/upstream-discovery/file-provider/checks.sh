
run_case_checks() {
  local response="" state="" seen_alt seen_primary attempt
  seen_alt=0
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    if ! jq -e '.body | fromjson | ([.servers[] | select(.source == "file" and .origin == "http://mock-alt:18081/alt" and .healthy == true)] | length) == 1' <<<"${state}" >/dev/null; then
      sleep 0.5
      continue
    fi
    response="$(client_request "example.test" "/app/file-discovery-${attempt}" 200)"
    if jq -e '.body | fromjson | .upstream == "alt-upstream"' <<<"${response}" >/dev/null; then
      seen_alt=1
      break
    fi
    sleep 0.5
  done
  if [[ "${seen_alt}" != "1" ]]; then
    echo "${state}" >&2
    echo "${response}" >&2
    fail_with_diagnostics "file discovery did not route to discovered upstream"
  fi

  cat >"${case_dir}/config/discovery/app-pool.json" <<'JSON'
{
  "servers": []
}
JSON
  docker cp "${case_dir}/config/discovery/app-pool.json" "${proxy_container}:/etc/oxibelt/config/discovery/app-pool.json"
  response=""
  seen_primary=0
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    state="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/upstream-pools/app-pool" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
    if ! jq -e '.body | fromjson | ([.servers[] | select(.source == "file" and .origin == "http://mock-alt:18081/alt")] | length) == 0' <<<"${state}" >/dev/null; then
      sleep 0.5
      continue
    fi
    response="$(client_request "example.test" "/app/file-discovery-after-remove-${attempt}" 200)"
    if jq -e '.body | fromjson | .upstream == "http-upstream"' <<<"${response}" >/dev/null; then
      seen_primary=1
      break
    fi
    sleep 0.5
  done
  if [[ "${seen_primary}" != "1" ]]; then
    echo "${state}" >&2
    echo "${response}" >&2
    fail_with_diagnostics "file discovery did not remove discovered upstream"
  fi
}
