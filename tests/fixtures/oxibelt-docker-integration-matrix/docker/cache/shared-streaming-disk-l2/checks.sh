
run_case_checks() {
  local path first_file second_file first second chunk_keys offline
  path="/app/shared-streaming-l2?sequence_key=shared-streaming-l2&body_repeat=131072&body_repeat_char=L&cache_control=public&content_type=text/plain&header_delay_ms=400"
  first_file="${work_dir}/shared-streaming-l2-first.json"
  second_file="${work_dir}/shared-streaming-l2-second.json"

  client_request "example.test" "${path}" 200 >"${first_file}"
  first="$(cat "${first_file}")"
  assert_response_jq "${first}" '(.body | length) == 131072 and .headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored" and .headers["x-sequence-index"] == "0"'

  for _attempt in $(seq 1 50); do
    chunk_keys="$(docker exec "${redis_container}" sh -c 'if command -v valkey-cli >/dev/null 2>&1; then valkey-cli KEYS "matrix-shared-cache-streaming:cache:chunk:*"; else redis-cli KEYS "matrix-shared-cache-streaming:cache:chunk:*"; fi')"
    if [[ -n "${chunk_keys}" ]]; then
      break
    fi
    sleep 0.2
  done
  if [[ -z "${chunk_keys}" ]]; then
    fail_with_diagnostics "expected streaming shared cache chunks in Redis"
  fi

  client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${path}" 200 "GET" "" >"${second_file}"
  second="$(cat "${second_file}")"
  assert_response_jq "${second}" '(.body | length) == 131072 and .headers["x-oxibelt-cache"] == "hit" and .headers["x-sequence-index"] == "0"'

  docker rm -f "${http_container}" >/dev/null
  offline="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${path}" 200 "GET" "")"
  assert_response_jq "${offline}" '(.body | length) == 131072 and .headers["x-oxibelt-cache"] == "hit"'
}
