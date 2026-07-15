
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

mock_fault_gate_request() {
  local method="$1" path="$2"
  docker exec "${http_container}" python /opt/mock_upstream/client.py \
    --target-host 127.0.0.1 \
    --scheme http \
    --port 18080 \
    --host mock-http \
    --method "${method}" \
    --path "${path}" \
    --body "" \
    --dump-response-json \
    --expect-status 200 \
    --timeout 2
}

run_case_checks() {
  local gate_id="cache-stampede"
  local request_path gate_status metrics baseline_waiters observed_waiters final_waiters
  local burst_file burst_pid=""
  request_path="/app/collapse?body=collapsed&cache_control=public&content_type=text/plain&sequence_key=p2-6-cache-stampede&gate=${gate_id}&gate_timeout_ms=15000"
  burst_file="${work_dir}/cache-stampede.json"

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  baseline_waiters="$(cache_metric_value "${metrics}" "oxibelt_cache_fill_waiters_total")"
  if [[ ! "${baseline_waiters}" =~ ^[0-9]+$ ]]; then
    fail_with_diagnostics "missing baseline cache fill waiter metric"
  fi

  "${repo_root}/tests/scripts/run-bounded-http-burst.sh" \
    --network "${network_name}" \
    --image "${mock_image}" \
    --label "${test_label}" \
    --target-host proxy \
    --port 8443 \
    --scheme https \
    --authority example.test \
    --path "${request_path}" \
    --allowed-statuses 200 \
    --concurrency 16 \
    --timeout-seconds 20 \
    --output "${burst_file}" \
    --ca-file "${cert_dir}/fullchain.pem" &
  burst_pid="$!"

  observed_waiters="${baseline_waiters}"
  for _ in $(seq 1 100); do
    gate_status="$(mock_fault_gate_request GET "/__fault/gates/${gate_id}")"
    metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
    observed_waiters="$(cache_metric_value "${metrics}" "oxibelt_cache_fill_waiters_total")"
    if jq -e '.body | fromjson | .waiting == 1 and .released == false' <<<"${gate_status}" >/dev/null \
      && [[ "${observed_waiters}" =~ ^[0-9]+$ ]] \
      && ((observed_waiters == baseline_waiters + 15)); then
      break
    fi
    sleep 0.1
  done
  if [[ ! "${observed_waiters}" =~ ^[0-9]+$ ]] || ((observed_waiters != baseline_waiters + 15)); then
    fail_with_diagnostics "cache stampede did not converge to one leader and fifteen bounded waiters"
  fi

  gate_status="$(mock_fault_gate_request POST "/__fault/gates/${gate_id}/release")"
  assert_response_jq "${gate_status}" '.body | fromjson | .released == true'
  if ! wait "${burst_pid}"; then
    fail_with_diagnostics "bounded cache stampede burst failed"
  fi
  burst_pid=""

  jq -e '
    length == 16
    and all(.[]; .status == 200 and .body == "collapsed")
    and all(.[]; .headers["x-sequence-index"] == "0")
    and ([.[] | select(.headers["x-oxibelt-cache"] == "miss")] | length) == 1
    and ([.[] | select(.headers["x-oxibelt-cache"] == "hit")] | length) == 15
  ' "${burst_file}" >/dev/null || fail_with_diagnostics "cache stampede responses did not collapse to one stored fill"

  metrics="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  final_waiters="$(cache_metric_value "${metrics}" "oxibelt_cache_fill_waiters_total")"
  if [[ "${final_waiters}" != "$((baseline_waiters + 15))" ]]; then
    fail_with_diagnostics "cache fill waiter metric did not record exactly fifteen followers"
  fi
  assert_response_jq "${metrics}" '.body | contains("oxibelt_cache_fill_lock_timeouts_total 0")'
  assert_response_jq "${metrics}" '.body | contains("oxibelt_cache_fill_errors_total 0")'

  docker stop --time 2 "${http_container}" >/dev/null
  local cached
  cached="$(client_request "example.test" "${request_path}" 200)"
  assert_response_jq "${cached}" '
    .body == "collapsed"
    and .headers["x-sequence-index"] == "0"
    and .headers["x-oxibelt-cache"] == "hit"
    and .headers["x-oxibelt-cache-reason"] == "fresh"
  '
}
