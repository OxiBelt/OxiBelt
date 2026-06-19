
run_case_checks() {
  local path first_file second_file third_file first second third metrics
  path="/app/stream-lock?body_repeat=131072&body_repeat_char=S&cache_control=public&content_type=text/plain&header_delay_ms=400"
  first_file="${work_dir}/stream-lock-first.json"
  second_file="${work_dir}/stream-lock-second.json"
  third_file="${work_dir}/stream-lock-third.json"
  client_request "example.test" "${path}" 200 >"${first_file}" &
  sleep 0.1
  client_request "example.test" "${path}" 200 >"${second_file}" &
  client_request "example.test" "${path}" 200 >"${third_file}" &
  wait
  first="$(cat "${first_file}")"
  second="$(cat "${second_file}")"
  third="$(cat "${third_file}")"
  assert_response_jq "${first}" '(.body | length) == 131072'
  assert_response_jq "${second}" '(.body | length) == 131072'
  assert_response_jq "${third}" '(.body | length) == 131072'
  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_cache_fill_lock_timeouts_total 0")'
}
