
retry_storm_gate_request() {
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

retry_storm_proxy_request() {
  local port="$1" host="$2" path="$3" expected="$4"
  docker exec "${http_container}" python /opt/mock_upstream/client.py \
    --target-host proxy \
    --scheme http \
    --port "${port}" \
    --host "${host}" \
    --method GET \
    --path "${path}" \
    --body "" \
    --dump-response-json \
    --expect-status "${expected}" \
    --timeout 2
}

retry_storm_metric_value() {
  local response="$1" metric="$2" label_name="$3" label_value="$4"
  jq -r '.body' <<<"${response}" | awk -v metric="${metric}" -v label_name="${label_name}" -v label_value="${label_value}" '
    index($1, metric "{") == 1 && index($0, label_name "=\"" label_value "\"") { value = $NF }
    END {
      if (value == "") exit 1
      print value
    }
  '
}

retry_storm_global_metric_value() {
  local response="$1" metric="$2" kind="$3"
  jq -r '.body' <<<"${response}" | awk -v metric="${metric}" -v kind="${kind}" '
    index($1, metric "{") == 1 && index($0, "scope_kind=\"global\"") && index($0, "scope=\"global\"") && index($0, "kind=\"" kind "\"") {
      value = $NF
    }
    END {
      if (value == "") exit 1
      print value
    }
  '
}

run_case_checks() {
  local gate_id="retry-storm" request_path burst_file burst_pid gate_status metrics live
  local original_attempts retry_attempts retry_rejections active_retry queued_retry
  local observed_budget="0"
  request_path="/status/503?body=retry-storm&content_type=text/plain&sequence_key=retry-storm&header_delay_sequence=0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|30000&gate=${gate_id}&gate_timeout_ms=15000"
  burst_file="${work_dir}/retry-storm.json"

  "${repo_root}/tests/scripts/run-bounded-http-burst.sh" \
    --network "${network_name}" \
    --image "${mock_image}" \
    --label "${test_label}" \
    --target-host proxy \
    --port 8443 \
    --scheme https \
    --authority example.test \
    --path "${request_path}" \
    --allowed-statuses 503 \
    --concurrency 16 \
    --timeout-seconds 10 \
    --output "${burst_file}" \
    --ca-file "${cert_dir}/fullchain.pem" &
  burst_pid="$!"

  for _ in $(seq 1 100); do
    gate_status="$(retry_storm_gate_request GET "/__fault/gates/${gate_id}")"
    if jq -e '.body | fromjson | .waiting == 16 and .released == false' <<<"${gate_status}" >/dev/null; then
      break
    fi
    sleep 0.1
  done
  if ! jq -e '.body | fromjson | .waiting == 16 and .released == false' <<<"${gate_status}" >/dev/null; then
    fail_with_diagnostics "retry storm originals did not synchronize at the upstream gate"
  fi

  gate_status="$(retry_storm_gate_request POST "/__fault/gates/${gate_id}/release")"
  assert_response_jq "${gate_status}" '.body | fromjson | .released == true'
  for _ in $(seq 1 100); do
    metrics="$(retry_storm_proxy_request 9090 ops.test /metrics 200)"
    active_retry="$(retry_storm_global_metric_value \
      "${metrics}" oxibelt_circuit_breaker_active retry)"
    queued_retry="$(retry_storm_global_metric_value \
      "${metrics}" oxibelt_circuit_breaker_queued retry)"
    observed_budget="$(retry_storm_metric_value "${metrics}" oxibelt_circuit_breaker_rejections_total reason retry_budget 2>/dev/null)" || true
    if [[ ! "${active_retry}" =~ ^[0-9]+$ || ! "${queued_retry}" =~ ^[0-9]+$ \
      || ! "${observed_budget}" =~ ^[0-9]+$ ]]; then
      fail_with_diagnostics "retry storm metrics were missing or nonnumeric during convergence"
    fi
    if ((10#${active_retry} > 1 || 10#${queued_retry} != 0 || 10#${observed_budget} > 15)); then
      printf 'Retry storm convergence state: active=%s queued=%s retry_budget_rejections=%s\n' \
        "${active_retry}" "${queued_retry}" "${observed_budget}" >&2
      fail_with_diagnostics "retry storm exceeded its one-active, zero-queued budget"
    fi
    if [[ "${observed_budget}" == "15" ]]; then
      break
    fi
    sleep 0.1
  done
  if [[ "${observed_budget}" != "15" ]]; then
    printf 'Retry storm final convergence state: active=%s queued=%s retry_budget_rejections=%s\n' \
      "${active_retry:-missing}" "${queued_retry:-missing}" "${observed_budget:-missing}" >&2
    fail_with_diagnostics "retry storm did not reach fifteen durable budget rejections"
  fi
  live="$(retry_storm_proxy_request 9091 ops.test /live 200)"
  assert_response_jq "${live}" '.body == "live"'

  if ! wait "${burst_pid}"; then
    fail_with_diagnostics "bounded retry storm burst failed"
  fi
  jq -e 'length == 16 and all(.[]; .status == 503)' "${burst_file}" >/dev/null \
    || fail_with_diagnostics "retry storm responses escaped the configured failure envelope"

  metrics="$(retry_storm_proxy_request 9090 ops.test /metrics 200)"
  original_attempts="$(retry_storm_metric_value "${metrics}" oxibelt_upstream_attempts_total kind original)"
  retry_attempts="$(retry_storm_metric_value "${metrics}" oxibelt_upstream_attempts_total kind retry)"
  retry_rejections="$(retry_storm_metric_value "${metrics}" oxibelt_circuit_breaker_rejections_total reason retry_budget)"
  active_retry="$(retry_storm_global_metric_value \
    "${metrics}" oxibelt_circuit_breaker_active retry)"
  queued_retry="$(retry_storm_global_metric_value \
    "${metrics}" oxibelt_circuit_breaker_queued retry)"
  if [[ "${original_attempts}" != "16" || "${retry_attempts}" != "1" || "${retry_rejections}" != "15" \
    || "${active_retry}" != "0" || "${queued_retry}" != "0" ]]; then
    fail_with_diagnostics "retry attempt, rejection, or final gauge invariants did not reconcile"
  fi

  local recovered
  recovered="$(client_request "example.test" "/status/200?body=recovered&content_type=text/plain&sequence_key=retry-storm" 200)"
  assert_response_jq "${recovered}" '.body == "recovered" and .headers["x-sequence-index"] == "17"'
}
