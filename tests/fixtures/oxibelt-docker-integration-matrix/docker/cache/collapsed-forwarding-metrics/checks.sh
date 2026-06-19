
run_case_checks() {
  local first_file second_file third_file first second third metrics
  first_file="${work_dir}/first-cache-fill.json"
  second_file="${work_dir}/second-cache-fill.json"
  third_file="${work_dir}/third-cache-fill.json"
  client_request "example.test" "/app/no-store-collapse?body=uncached&cache_control=no-store&content_type=text/plain&header_delay_ms=800" 200 >"${first_file}" &
  sleep 0.1
  client_request "example.test" "/app/no-store-collapse?body=uncached&cache_control=no-store&content_type=text/plain&header_delay_ms=800" 200 >"${second_file}" &
  client_request "example.test" "/app/no-store-collapse?body=uncached&cache_control=no-store&content_type=text/plain&header_delay_ms=800" 200 >"${third_file}" &
  wait
  first="$(cat "${first_file}")"
  second="$(cat "${second_file}")"
  third="$(cat "${third_file}")"
  assert_response_jq "${first}" '.body == "uncached"'
  assert_response_jq "${second}" '.body == "uncached"'
  assert_response_jq "${third}" '.body == "uncached"'

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_cache_fill_waiters_total 2")'
  assert_response_jq "${metrics}" '.body | contains("reason=\"fill_not_stored\"")'

  client_request "example.test" "/app/collapse?body=collapsed&cache_control=public&content_type=text/plain&header_delay_ms=800" 200 >"${first_file}" &
  sleep 0.1
  client_request "example.test" "/app/collapse?body=collapsed&cache_control=public&content_type=text/plain&header_delay_ms=800" 200 >"${second_file}" &
  wait
  first="$(cat "${first_file}")"
  second="$(cat "${second_file}")"
  assert_response_jq "${first}" '.body == "collapsed"'
  assert_response_jq "${second}" '.body == "collapsed"'

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_cache_fill_waiters_total 3")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_cache_fill_lock_timeouts_total 0")'
}
