
redis_disconnect_probe() {
  local port="$1" host="$2" path="$3" expected="$4"
  docker exec "${http_container}" python /opt/mock_upstream/client.py \
    --scheme http \
    --target-host proxy \
    --port "${port}" \
    --host "${host}" \
    --path "${path}" \
    --method GET \
    --body "" \
    --timeout 2 \
    --dump-response-json \
    --expect-status "${expected}"
}

redis_disconnect_metric_value() {
  local response="$1" metric="$2" label_name="${3:-}" label_value="${4:-}"
  jq -r '.body' <<<"${response}" | awk -v metric="${metric}" -v label_name="${label_name}" -v label_value="${label_value}" '
    index($1, metric "{") == 1 && index($0, "backend=\"cluster\"") && index($0, "kind=\"redis\"") && (label_name == "" || index($0, label_name "=\"" label_value "\"")) {
      value = $NF
    }
    END {
      if (value == "") exit 1
      print value
    }
  '
}

run_case_checks() {
  local warm live metrics burst_file burst_pid discarded reconnect_failed circuit_open active waiting
  local recovered="" created recoveries circuit_closed
  warm="$(redis_disconnect_probe 8080 example.test /app/disconnect/warm 200)"
  assert_response_jq "${warm}" '.body | contains("/origin/app/disconnect/warm")'

  docker stop --time 2 "${redis_container}" >/dev/null
  burst_file="${work_dir}/redis-disconnect-burst.json"
  "${repo_root}/tests/scripts/run-bounded-http-burst.sh" \
    --network "${network_name}" \
    --image "${mock_image}" \
    --label "${test_label}" \
    --target-host proxy \
    --port 8443 \
    --scheme https \
    --authority example.test \
    --path /app/disconnect/fault \
    --allowed-statuses 503 \
    --concurrency 8 \
    --timeout-seconds 6 \
    --output "${burst_file}" \
    --ca-file "${cert_dir}/fullchain.pem" &
  burst_pid="$!"

  live="$(redis_disconnect_probe 9091 ops.test /live 200)"
  assert_response_jq "${live}" '.body == "live"'
  metrics="$(redis_disconnect_probe 9090 ops.test /metrics 200)"
  assert_response_jq "${metrics}" '.body | contains("oxibelt_shared_state_pool_")'

  if ! wait "${burst_pid}"; then
    fail_with_diagnostics "Redis disconnect burst did not fail closed with bounded 503 responses"
  fi
  jq -e 'length == 8 and all(.[]; .status == 503)' "${burst_file}" >/dev/null \
    || fail_with_diagnostics "Redis disconnect burst returned unexpected responses"

  metrics="$(redis_disconnect_probe 9090 ops.test /metrics 200)"
  discarded="$(redis_disconnect_metric_value "${metrics}" oxibelt_shared_state_pool_connection_events_total event discarded)" || true
  reconnect_failed="$(redis_disconnect_metric_value "${metrics}" oxibelt_shared_state_pool_connection_events_total event reconnect_failed)" || true
  circuit_open="$(redis_disconnect_metric_value "${metrics}" oxibelt_shared_state_pool_acquisitions_total outcome circuit_open)" || true
  if [[ ! "${discarded}" =~ ^[0-9]+$ ]] || ((discarded < 1)) \
    || [[ ! "${reconnect_failed}" =~ ^[0-9]+$ ]] || ((reconnect_failed < 1 || reconnect_failed > 8)) \
    || [[ ! "${circuit_open}" =~ ^[0-9]+$ ]] || ((circuit_open < 1)); then
    fail_with_diagnostics "Redis disconnect telemetry did not prove bounded reconnect attempts and circuit-open rejection"
  fi
  if ! jq -r '.body' <<<"${metrics}" \
    | grep -F 'oxibelt_backend_feature_degraded{feature="rate_limits",backend="cluster",kind="redis",mode="fail_closed"} 1' >/dev/null; then
    fail_with_diagnostics "Redis disconnect did not mark the rate-limit backend degraded"
  fi

  docker start "${redis_container}" >/dev/null
  for _ in $(seq 1 40); do
    if recovered="$(redis_disconnect_probe 8080 example.test /app/disconnect/recovered 200 2>/dev/null)"; then
      break
    fi
    sleep 0.2
  done
  if ! jq -e '.status == 200 and (.body | contains("/origin/app/disconnect/recovered"))' <<<"${recovered}" >/dev/null 2>&1; then
    fail_with_diagnostics "Redis pool did not recover through a fresh connection"
  fi

  # A second successful operation refreshes the exported pool snapshot after
  # the half-open connection attempt has closed the reconnect circuit.
  recovered="$(redis_disconnect_probe 8080 example.test /app/disconnect/recovered-confirm 200)"
  assert_response_jq "${recovered}" '.body | contains("/origin/app/disconnect/recovered-confirm")'

  for _ in $(seq 1 50); do
    metrics="$(redis_disconnect_probe 9090 ops.test /metrics 200)"
    active="$(redis_disconnect_metric_value "${metrics}" oxibelt_shared_state_pool_connections state active)" || true
    waiting="$(redis_disconnect_metric_value "${metrics}" oxibelt_shared_state_pool_waiters)" || true
    circuit_closed="$(redis_disconnect_metric_value "${metrics}" oxibelt_shared_state_pool_circuit_state state closed)" || true
    if [[ "${active}" == "0" && "${waiting}" == "0" && "${circuit_closed}" == "1" ]]; then
      break
    fi
    sleep 0.2
  done
  if [[ "${active}" != "0" || "${waiting}" != "0" || "${circuit_closed}" != "1" ]]; then
    printf 'Redis final pool state: active=%s waiting=%s circuit_closed=%s\n' \
      "${active:-missing}" "${waiting:-missing}" "${circuit_closed:-missing}" >&2
    fail_with_diagnostics "Redis pool did not drain work and close its reconnect circuit"
  fi
  created="$(redis_disconnect_metric_value "${metrics}" oxibelt_shared_state_pool_connection_events_total event created)" || true
  if [[ ! "${created}" =~ ^[0-9]+$ ]] || ((created < 2)); then
    fail_with_diagnostics "Redis reconnect did not create a replacement pooled connection"
  fi
  recoveries="$(jq -r '.body' <<<"${metrics}" | awk '
    index($1, "oxibelt_backend_feature_recoveries_total{") == 1 && index($0, "feature=\"rate_limits\"") && index($0, "backend=\"cluster\"") && index($0, "kind=\"redis\"") && index($0, "mode=\"fail_closed\"") { value = $NF }
    END { print value }
  ')"
  if [[ ! "${recoveries}" =~ ^[0-9]+$ ]] || ((recoveries < 1)); then
    fail_with_diagnostics "Redis reconnect did not record backend recovery"
  fi
  live="$(redis_disconnect_probe 9091 ops.test /live 200)"
  assert_response_jq "${live}" '.headers["x-oxibelt-backend-status"] == "healthy"'
}
