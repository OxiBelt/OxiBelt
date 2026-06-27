
cache_metric_value() {
  local metrics="$1" metric="$2"
  jq -r --arg metric "${metric}" '
    .body
    | split("\n")
    | map(select(startswith($metric + " ")))
    | .[0] // ""
    | split(" ")
    | .[1] // empty
  ' <<<"${metrics}"
}

require_cache_metric_at_least() {
  local metrics="$1" metric="$2" minimum="$3" actual
  actual="$(cache_metric_value "${metrics}" "${metric}")"
  if [[ ! "${actual}" =~ ^[0-9]+$ ]] || ((actual < minimum)); then
    echo "Expected ${metric} >= ${minimum}, got ${actual:-missing}" >&2
    fail_with_diagnostics "cache metric assertion failed"
  fi
  printf '%s' "${actual}"
}

run_case_checks() {
  local first_file second_file third_file first second third metrics no_store_waiters cacheable_waiters
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
  no_store_waiters="$(require_cache_metric_at_least "${metrics}" "oxibelt_cache_fill_waiters_total" 1)"
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
  cacheable_waiters="$(require_cache_metric_at_least "${metrics}" "oxibelt_cache_fill_waiters_total" "$((no_store_waiters + 1))")"
  if ((cacheable_waiters <= no_store_waiters)); then
    echo "Expected oxibelt_cache_fill_waiters_total to increase after cacheable collapse, got ${cacheable_waiters} after ${no_store_waiters}" >&2
    fail_with_diagnostics "cache waiter metric did not increase"
  fi
  assert_response_jq "${metrics}" '.body | contains("oxibelt_cache_fill_lock_timeouts_total 0")'
}
