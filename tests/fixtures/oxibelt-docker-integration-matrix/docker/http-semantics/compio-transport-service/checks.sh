compio_transport_control_stats() {
  docker exec "${http_container}" python /opt/mock_upstream/client.py \
    --target-host 127.0.0.1 \
    --scheme http \
    --port 18081 \
    --host mock-control \
    --method GET \
    --path /__control/stats \
    --body "" \
    --dump-response-json \
    --expect-status 200 \
    --timeout 2
}

compio_transport_alt_control_stats() {
  docker exec "${alt_container}" python /opt/mock_upstream/client.py \
    --target-host 127.0.0.1 \
    --scheme http \
    --port 18082 \
    --host mock-control \
    --method GET \
    --path /__control/stats \
    --body "" \
    --dump-response-json \
    --expect-status 200 \
    --timeout 2
}

compio_transport_alt_gate_request() {
  local method="$1" path="$2"
  docker exec "${alt_container}" python /opt/mock_upstream/client.py \
    --target-host 127.0.0.1 \
    --scheme http \
    --port 18081 \
    --host mock-alt \
    --method "${method}" \
    --path "${path}" \
    --body "" \
    --dump-response-json \
    --expect-status 200 \
    --timeout 2
}

compio_transport_connection_count() {
  local stats="$1" field="$2"
  local value
  value="$(
    jq -r --arg field "${field}" \
      '.body | fromjson | .connections[$field] // 0' <<<"${stats}"
  )"
  compio_transport_require_canonical_nonnegative_decimal \
    "${value}" \
    "mock upstream connection count ${field}"
}

compio_transport_operation_count() {
  local stats="$1" operation_id="$2"
  local value
  value="$(
    jq -r --arg key "operation.${operation_id}" \
      '.body | fromjson | .request_counts[$key] // 0' <<<"${stats}"
  )"
  compio_transport_require_canonical_nonnegative_decimal \
    "${value}" \
    "mock upstream operation count"
}

compio_transport_require_canonical_nonnegative_decimal() {
  local value="$1" metric_name="$2"
  if [[ ! "${value}" =~ ^(0|[1-9][0-9]*)$ ]]; then
    fail_with_diagnostics \
      "metric ${metric_name} did not contain a canonical nonnegative decimal"
    return 1
  fi
  printf '%s' "${value}"
}

compio_transport_backend_metric_value() {
  local metrics="$1" backend="$2" outcome="$3"
  local metric_name="oxibelt_http_direct_h1_io_backend_total"
  local value
  value="$(
    jq -r \
      --arg backend "${backend}" \
      --arg outcome "${outcome}" '
        (
          "oxibelt_http_direct_h1_io_backend_total{backend=\""
          + $backend
          + "\",protocol=\"h1\",outcome=\""
          + $outcome
          + "\"} "
        ) as $prefix
        | .body
        | split("\n")
        | map(select(startswith($prefix)))
        | .[0] // ""
        | split(" ")
        | .[1] // "0"
      ' <<<"${metrics}"
  )"
  compio_transport_require_canonical_nonnegative_decimal "${value}" "${metric_name}"
}

compio_transport_service_metric_value() {
  local metrics="$1" metric="$2" label_name="$3" label_value="$4"
  local value
  value="$(
    jq -r \
      --arg metric "${metric}" \
      --arg label_name "${label_name}" \
      --arg label_value "${label_value}" '
        (
          $metric
          + "{"
          + $label_name
          + "=\""
          + $label_value
          + "\"} "
        ) as $prefix
        | .body
        | split("\n")
        | map(select(startswith($prefix)))
        | .[0] // ""
        | split(" ")
        | .[1] // "0"
      ' <<<"${metrics}"
  )"
  compio_transport_require_canonical_nonnegative_decimal "${value}" "${metric}"
}

compio_transport_unlabelled_metric_value() {
  local metrics="$1" metric="$2"
  local value
  value="$(
    jq -r \
      --arg prefix "${metric} " '
        .body
        | split("\n")
        | map(select(startswith($prefix)))
        | .[0] // ""
        | split(" ")
        | .[1] // "0"
      ' <<<"${metrics}"
  )"
  compio_transport_require_canonical_nonnegative_decimal "${value}" "${metric}"
}

compio_transport_require_exact_metric_sample() {
  local metrics="$1" sample="$2" value="$3"
  if ! jq -e \
    --arg expected "${sample} ${value}" \
    '.body | split("\n") | index($expected) != null' \
    <<<"${metrics}" >/dev/null; then
    fail_with_diagnostics \
      "missing exact runtime topology metric sample ${sample} ${value}"
    return 1
  fi
}

compio_transport_expect_response_body_failure() {
  local path="$1"
  local client_container output=""
  client_container="$(unique_docker_container_name "oxibelt-compio-body-failure-client")"
  docker create \
    --name "${client_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" \
    /opt/mock_upstream/client.py \
    --target-host proxy \
    --server-name proxy \
    --path "${path}" \
    --host example.test \
    --port 8443 \
    --method GET \
    --body "" \
    --ca-file /tmp/proxy-ca.pem \
    --dump-response-json \
    --expect-status 200 >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/proxy-ca.pem"
  if output="$(docker_start_stdout_only "${client_container}")"; then
    docker rm -f "${client_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics \
      "truncated Compio response unexpectedly completed successfully: ${output}"
  fi
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
}

run_case_checks() {
  local stats_before stats_after accepted_before accepted_after response
  local metrics_before metrics_after
  local compio_selected_before compio_selected_after
  local compio_fallback_before compio_fallback_after
  local hyper_selected_before hyper_selected_after
  local capacity_stats_before capacity_stats_after
  local capacity_accepted_before capacity_accepted_after capacity_burst_file capacity_burst_pid
  local capacity_expected_connections capacity_gate_polls=0 capacity_gate_status
  local capacity_metrics_before capacity_metrics_after
  local capacity_compio_selected_before capacity_compio_selected_after
  local capacity_compio_fallback_before capacity_compio_fallback_after
  local capacity_compio_error_before capacity_compio_error_after
  local capacity_hyper_selected_before capacity_hyper_selected_after
  local capacity_dispatch_fallback_before capacity_dispatch_fallback_after
  local capacity_dispatch_rejection_before capacity_dispatch_rejection_after
  local half_close_metrics_before half_close_metrics_after
  local half_close_eof_before half_close_eof_after
  local half_close_io_before half_close_io_after
  local half_close_cancel_before half_close_cancel_after
  local operation_id

  capacity_stats_before="$(compio_transport_alt_control_stats)"
  capacity_accepted_before="$(compio_transport_connection_count \
    "${capacity_stats_before}" accepted)"
  capacity_metrics_before="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  capacity_compio_selected_before="$(compio_transport_backend_metric_value \
    "${capacity_metrics_before}" compio selected)"
  capacity_compio_fallback_before="$(compio_transport_backend_metric_value \
    "${capacity_metrics_before}" compio fallback)"
  capacity_compio_error_before="$(compio_transport_backend_metric_value \
    "${capacity_metrics_before}" compio error)"
  capacity_hyper_selected_before="$(compio_transport_backend_metric_value \
    "${capacity_metrics_before}" tokio_hyper selected)"
  capacity_dispatch_fallback_before="$(compio_transport_service_metric_value \
    "${capacity_metrics_before}" \
    oxibelt_http_compio_direct_h1_dispatch_total \
    outcome \
    predispatch_fallback)"
  capacity_dispatch_rejection_before="$(compio_transport_service_metric_value \
    "${capacity_metrics_before}" \
    oxibelt_http_compio_direct_h1_dispatch_total \
    outcome \
    predispatch_rejection)"
  capacity_burst_file="${work_dir}/compio-capacity-burst.json"

  "${repo_root}/tests/scripts/run-bounded-http-burst.sh" \
    --network "${network_name}" \
    --image "${mock_image}" \
    --label "${test_label}" \
    --target-host proxy \
    --port 8443 \
    --scheme https \
    --authority capacity.example.test \
    --path "/capacity-limit?operation_id=capacity-burst&body=capacity&content_type=text/plain&gate=compio-capacity&gate_timeout_ms=10000" \
    --allowed-statuses 200,503 \
    --concurrency 3 \
    --timeout-seconds 10 \
    --output "${capacity_burst_file}" \
    --ca-file "${cert_dir}/fullchain.pem" &
  capacity_burst_pid="$!"

  for _ in {1..100}; do
    capacity_gate_status="$(compio_transport_alt_gate_request \
      GET /__fault/gates/compio-capacity)"
    capacity_gate_polls="$((capacity_gate_polls + 1))"
    if jq -e \
      '.body | fromjson | .waiting == 2 and .released == false' \
      <<<"${capacity_gate_status}" >/dev/null; then
      break
    fi
    sleep 0.1
  done
  if ! jq -e \
    '.body | fromjson | .waiting == 2 and .released == false' \
    <<<"${capacity_gate_status}" >/dev/null; then
    compio_transport_alt_gate_request \
      POST /__fault/gates/compio-capacity/release >/dev/null 2>&1 || true
    wait "${capacity_burst_pid}" >/dev/null 2>&1 || true
    fail_with_diagnostics \
      "Compio capacity burst did not stop at exactly two admitted origin operations"
  fi
  capacity_gate_status="$(compio_transport_alt_gate_request \
    POST /__fault/gates/compio-capacity/release)"
  assert_response_jq \
    "${capacity_gate_status}" \
    '.body | fromjson | .released == true'
  if ! wait "${capacity_burst_pid}"; then
    fail_with_diagnostics "Compio capacity burst client failed after gate release"
  fi

  if ! jq -e '
    ([.[].status] | sort) == [200, 200, 503]
    and ([.[] | select(.status == 200 and .body == "capacity")] | length) == 2
    and ([.[]
      | select(
          .status == 503
          and .body == "request admission unavailable"
          and .headers["retry-after"] == "3"
        )
      ] | length) == 1
  ' "${capacity_burst_file}" >/dev/null; then
    fail_with_diagnostics \
      "Compio capacity burst did not return two successes and one typed admission rejection"
  fi

  capacity_stats_after="$(compio_transport_alt_control_stats)"
  capacity_accepted_after="$(compio_transport_connection_count \
    "${capacity_stats_after}" accepted)"
  # Every bounded gate poll and the release request use the mock's main port,
  # so they are included in its accepted-connection counter. After removing
  # those exact control connections, only the two admitted burst connections
  # may remain; a Hyper escape would add a third.
  capacity_expected_connections="$((capacity_gate_polls + 3))"
  if ((capacity_accepted_after - capacity_accepted_before != capacity_expected_connections)); then
    fail_with_diagnostics \
      "Compio capacity burst escaped the two-connection per-origin limit; before=${capacity_accepted_before} after=${capacity_accepted_after} gate_polls=${capacity_gate_polls}"
  fi
  if [[ "$(compio_transport_operation_count \
    "${capacity_stats_after}" capacity-burst)" != "2" ]]; then
    fail_with_diagnostics \
      "Compio capacity rejection reached the alternate origin instead of failing closed"
  fi

  capacity_metrics_after="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  capacity_compio_selected_after="$(compio_transport_backend_metric_value \
    "${capacity_metrics_after}" compio selected)"
  capacity_compio_fallback_after="$(compio_transport_backend_metric_value \
    "${capacity_metrics_after}" compio fallback)"
  capacity_compio_error_after="$(compio_transport_backend_metric_value \
    "${capacity_metrics_after}" compio error)"
  capacity_hyper_selected_after="$(compio_transport_backend_metric_value \
    "${capacity_metrics_after}" tokio_hyper selected)"
  capacity_dispatch_fallback_after="$(compio_transport_service_metric_value \
    "${capacity_metrics_after}" \
    oxibelt_http_compio_direct_h1_dispatch_total \
    outcome \
    predispatch_fallback)"
  capacity_dispatch_rejection_after="$(compio_transport_service_metric_value \
    "${capacity_metrics_after}" \
    oxibelt_http_compio_direct_h1_dispatch_total \
    outcome \
    predispatch_rejection)"
  if ((capacity_compio_selected_after - capacity_compio_selected_before != 3)); then
    fail_with_diagnostics "capacity burst should select Compio exactly three times"
  fi
  if ((capacity_compio_error_after - capacity_compio_error_before != 1)); then
    fail_with_diagnostics "capacity burst should record exactly one Compio error"
  fi
  if ((capacity_compio_fallback_after - capacity_compio_fallback_before != 0)); then
    fail_with_diagnostics "capacity rejection must not record a Compio fallback"
  fi
  if ((capacity_hyper_selected_after - capacity_hyper_selected_before != 0)); then
    fail_with_diagnostics "capacity rejection must not select Hyper"
  fi
  if ((capacity_dispatch_fallback_after - capacity_dispatch_fallback_before != 0)); then
    fail_with_diagnostics "capacity rejection must not record a pre-dispatch fallback"
  fi
  if ((capacity_dispatch_rejection_after - capacity_dispatch_rejection_before != 1)); then
    fail_with_diagnostics "capacity burst should record exactly one pre-dispatch rejection"
  fi

  stats_before="$(compio_transport_control_stats)"
  accepted_before="$(compio_transport_connection_count "${stats_before}" accepted)"

  for operation_id in reuse-1 reuse-2 reuse-3 reuse-4; do
    response="$(client_request \
      "example.test" \
      "/reuse?operation_id=${operation_id}&body=${operation_id}&content_type=text/plain" \
      200)"
    assert_response_jq "${response}" ".body == \"${operation_id}\""
  done

  stats_after="$(compio_transport_control_stats)"
  accepted_after="$(compio_transport_connection_count "${stats_after}" accepted)"
  if ((accepted_after - accepted_before != 1)); then
    fail_with_diagnostics \
      "four sequential Compio requests should reuse one accepted upstream connection; before=${accepted_before} after=${accepted_after}"
  fi
  for operation_id in reuse-1 reuse-2 reuse-3 reuse-4; do
    if [[ "$(compio_transport_operation_count "${stats_after}" "${operation_id}")" != "1" ]]; then
      fail_with_diagnostics "sequential Compio request ${operation_id} was not observed exactly once"
    fi
  done

  stats_before="${stats_after}"
  accepted_before="${accepted_after}"
  response="$(client_request \
    "example.test" \
    "/fault?operation_id=malformed-once&h1_fault=malformed_head" \
    502)"
  assert_response_jq "${response}" '.status == 502'
  response="$(client_request \
    "example.test" \
    "/recovered?operation_id=after-malformed&body=recovered&content_type=text/plain" \
    200)"
  assert_response_jq "${response}" '.body == "recovered"'
  stats_after="$(compio_transport_control_stats)"
  accepted_after="$(compio_transport_connection_count "${stats_after}" accepted)"
  if ((accepted_after - accepted_before != 1)); then
    fail_with_diagnostics \
      "a malformed response on the reused connection must force one new recovery connection; before=${accepted_before} after=${accepted_after}"
  fi
  if [[ "$(compio_transport_operation_count "${stats_after}" malformed-once)" != "1" ]]; then
    fail_with_diagnostics "the malformed post-dispatch request was sent more than once"
  fi

  stats_before="${stats_after}"
  accepted_before="${accepted_after}"
  response="$(client_request \
    "example.test" \
    "/prefabricated?operation_id=prefabricated-once&h1_fault=prefabricated_response" \
    200)"
  assert_response_jq "${response}" '.body == "ok"'
  response="$(client_request \
    "example.test" \
    "/after-prefabricated?operation_id=after-prefabricated&body=clean&content_type=text/plain" \
    200)"
  assert_response_jq "${response}" '.body == "clean"'
  stats_after="$(compio_transport_control_stats)"
  accepted_after="$(compio_transport_connection_count "${stats_after}" accepted)"
  if ((accepted_after - accepted_before != 1)); then
    fail_with_diagnostics \
      "socket-resident response bytes must retire the poisoned connection before the next request; before=${accepted_before} after=${accepted_after}"
  fi
  if [[ "$(compio_transport_operation_count "${stats_after}" prefabricated-once)" != "1" ]]; then
    fail_with_diagnostics "the prefabricated-response request was not observed exactly once"
  fi
  if [[ "$(compio_transport_operation_count "${stats_after}" after-prefabricated)" != "1" ]]; then
    fail_with_diagnostics "the request after a prefabricated response was not observed exactly once"
  fi

  stats_before="${stats_after}"
  accepted_before="${accepted_after}"
  half_close_metrics_before="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  half_close_eof_before="$(compio_transport_service_metric_value \
    "${half_close_metrics_before}" \
    oxibelt_http_compio_direct_h1_connection_events_total \
    event \
    retired_eof)"
  half_close_io_before="$(compio_transport_service_metric_value \
    "${half_close_metrics_before}" \
    oxibelt_http_compio_direct_h1_connection_events_total \
    event \
    retired_io_error)"
  half_close_cancel_before="$(compio_transport_service_metric_value \
    "${half_close_metrics_before}" \
    oxibelt_http_compio_direct_h1_connection_events_total \
    event \
    retired_cancellation)"
  compio_transport_expect_response_body_failure \
    "/half-close?operation_id=half-close-once&h1_fault=half_close_after_head"
  response="$(client_request \
    "example.test" \
    "/after-half-close?operation_id=after-half-close&body=after-half-close&content_type=text/plain" \
    200)"
  assert_response_jq "${response}" '.body == "after-half-close"'
  stats_after="$(compio_transport_control_stats)"
  accepted_after="$(compio_transport_connection_count "${stats_after}" accepted)"
  if ((accepted_after - accepted_before != 1)); then
    fail_with_diagnostics \
      "a half-closed reused connection must force one new recovery connection; before=${accepted_before} after=${accepted_after}"
  fi
  if [[ "$(compio_transport_operation_count "${stats_after}" half-close-once)" != "1" ]]; then
    fail_with_diagnostics "the half-close post-dispatch request was sent more than once"
  fi
  # The polling and io_uring drivers may surface a peer half-close as clean
  # EOF, a reset-style read error, or a racing downstream body cancellation.
  # All three are terminal and non-reusable. The response-body channel reports
  # its failure before the worker has necessarily finished terminal FD cleanup,
  # so poll the metrics endpoint for that bounded asynchronous completion.
  for _ in {1..50}; do
    half_close_metrics_after="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
    half_close_eof_after="$(compio_transport_service_metric_value \
      "${half_close_metrics_after}" \
      oxibelt_http_compio_direct_h1_connection_events_total \
      event \
      retired_eof)"
    half_close_io_after="$(compio_transport_service_metric_value \
      "${half_close_metrics_after}" \
      oxibelt_http_compio_direct_h1_connection_events_total \
      event \
      retired_io_error)"
    half_close_cancel_after="$(compio_transport_service_metric_value \
      "${half_close_metrics_after}" \
      oxibelt_http_compio_direct_h1_connection_events_total \
      event \
      retired_cancellation)"
    if (( (half_close_eof_after - half_close_eof_before)
        + (half_close_io_after - half_close_io_before)
        + (half_close_cancel_after - half_close_cancel_before) != 0 )); then
      break
    fi
    sleep 0.1
  done
  # Pin the exact one-operation delta around this request instead of making
  # the fixture backend-dependent.
  if (( (half_close_eof_after - half_close_eof_before)
      + (half_close_io_after - half_close_io_before)
      + (half_close_cancel_after - half_close_cancel_before) != 1 )); then
    fail_with_diagnostics \
      "half-close response did not record exactly one terminal retirement; eof=${half_close_eof_before}->${half_close_eof_after} io=${half_close_io_before}->${half_close_io_after} cancellation=${half_close_cancel_before}->${half_close_cancel_after}"
  fi

  stats_before="${stats_after}"
  accepted_before="${accepted_after}"
  response="$(client_request \
    "example.test" \
    "/close?operation_id=peer-close&h1_fault=close_after_body" \
    200)"
  assert_response_jq "${response}" '.body == "ok"'
  response="$(client_request \
    "example.test" \
    "/after-close?operation_id=after-peer-close&body=after-close&content_type=text/plain" \
    200)"
  assert_response_jq "${response}" '.body == "after-close"'
  stats_after="$(compio_transport_control_stats)"
  accepted_after="$(compio_transport_connection_count "${stats_after}" accepted)"
  if ((accepted_after - accepted_before != 1)); then
    fail_with_diagnostics \
      "Connection: close on the reused connection must force one new recovery connection; before=${accepted_before} after=${accepted_after}"
  fi

  metrics_before="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  compio_selected_before="$(
    compio_transport_backend_metric_value "${metrics_before}" compio selected
  )"
  compio_fallback_before="$(
    compio_transport_backend_metric_value "${metrics_before}" compio fallback
  )"
  hyper_selected_before="$(
    compio_transport_backend_metric_value "${metrics_before}" tokio_hyper selected
  )"

  response="$(client_request_with_headers \
    "example.test" \
    "/bodyful?operation_id=fixed-post&content_type=text/plain" \
    200 \
    "POST" \
    "fixed-body" \
    "Content-Type: text/plain")"
  assert_body_jq "${response}" '.body == "fixed-body"'
  response="$(split_body_client_request \
    "example.test" \
    "/bodyful?operation_id=split-post&content_type=text/plain" \
    200 \
    "POST" \
    "split-body" \
    5 \
    100 \
    "Content-Type: text/plain")"
  assert_body_jq "${response}" '.body == "split-body"'

  metrics_after="$(plain_client_request_on_port 9090 "ops.test" "/metrics" 200)"
  compio_selected_after="$(
    compio_transport_backend_metric_value "${metrics_after}" compio selected
  )"
  compio_fallback_after="$(
    compio_transport_backend_metric_value "${metrics_after}" compio fallback
  )"
  hyper_selected_after="$(
    compio_transport_backend_metric_value "${metrics_after}" tokio_hyper selected
  )"
  if ((compio_selected_after - compio_selected_before != 0)); then
    fail_with_diagnostics "bodyful controls must remain off the Compio wire path"
  fi
  if ((compio_fallback_after - compio_fallback_before != 2)); then
    fail_with_diagnostics "bodyful controls should record exactly two Compio pre-dispatch fallbacks"
  fi
  if ((hyper_selected_after - hyper_selected_before != 2)); then
    fail_with_diagnostics "bodyful controls should select Hyper exactly twice"
  fi
  if ((compio_selected_after < 1)); then
    fail_with_diagnostics \
      "runtime topology reported Compio direct-H1 without an actually selected Compio request"
  fi

  compio_transport_require_exact_metric_sample \
    "${metrics_after}" \
    'oxibelt_runtime_topology_info{requested_preset="compio",resolved_preset="hybrid_compio",outcome="exact",reason="legacy_alias"}' \
    1
  compio_transport_require_exact_metric_sample \
    "${metrics_after}" \
    'oxibelt_runtime_subsystem_owner{subsystem="startup_orchestration",owner="compio"}' \
    1
  compio_transport_require_exact_metric_sample \
    "${metrics_after}" \
    'oxibelt_runtime_subsystem_owner{subsystem="general_http",owner="tokio"}' \
    1
  compio_transport_require_exact_metric_sample \
    "${metrics_after}" \
    'oxibelt_runtime_subsystem_owner{subsystem="direct_h1_transport",owner="compio"}' \
    1
  compio_transport_require_exact_metric_sample \
    "${metrics_after}" \
    'oxibelt_runtime_worker_allocation{pool="tokio_executor",owner="tokio"}' \
    1
  compio_transport_require_exact_metric_sample \
    "${metrics_after}" \
    'oxibelt_runtime_worker_allocation{pool="compio_direct_h1",owner="compio"}' \
    1

  stats_after="$(compio_transport_control_stats)"
  for operation_id in fixed-post split-post; do
    if [[ "$(compio_transport_operation_count "${stats_after}" "${operation_id}")" != "1" ]]; then
      fail_with_diagnostics "bodyful Hyper control ${operation_id} reached the origin more than once"
    fi
  done

  for metric_name in \
    oxibelt_http_compio_direct_h1_submissions_total \
    oxibelt_http_compio_direct_h1_queue_occupancy \
    oxibelt_http_compio_direct_h1_workers \
    oxibelt_http_compio_direct_h1_connections \
    oxibelt_http_compio_direct_h1_connection_events_total \
    oxibelt_http_compio_direct_h1_dispatch_total \
    oxibelt_http_compio_direct_h1_buffer_events_total \
    oxibelt_http_compio_direct_h1_operation_wait_observations_total \
    oxibelt_http_compio_direct_h1_operation_wait_duration_ns_total \
    oxibelt_http_compio_direct_h1_connect_observations_total \
    oxibelt_http_compio_direct_h1_connect_duration_ns_total \
    oxibelt_http_compio_direct_h1_cancellation_observations_total \
    oxibelt_http_compio_direct_h1_cancellation_duration_ns_total \
    oxibelt_http_compio_direct_h1_copied_bytes_total; do
    if ! jq -e --arg metric "${metric_name}" \
      '.body | contains($metric)' <<<"${metrics_after}" >/dev/null; then
      fail_with_diagnostics "missing Compio transport service metric ${metric_name}"
    fi
  done

  if [[ "$(compio_transport_unlabelled_metric_value \
    "${metrics_after}" \
    oxibelt_http_compio_direct_h1_queue_occupancy)" != "0" ]]; then
    fail_with_diagnostics "Compio submission queue did not drain after the functional case"
  fi
  if (( $(compio_transport_service_metric_value \
    "${metrics_after}" \
    oxibelt_http_compio_direct_h1_submissions_total \
    outcome \
    immediate) < 1 )); then
    fail_with_diagnostics "Compio transport did not record immediate service admission"
  fi
  if (( $(compio_transport_service_metric_value \
    "${metrics_after}" \
    oxibelt_http_compio_direct_h1_connection_events_total \
    event \
    reused) < 3 )); then
    fail_with_diagnostics "Compio transport did not record the expected clean connection reuse"
  fi
  if (( $(compio_transport_service_metric_value \
    "${metrics_after}" \
    oxibelt_http_compio_direct_h1_connection_events_total \
    event \
    retired_protocol) < 1 )); then
    fail_with_diagnostics "malformed response did not record protocol retirement"
  fi
  if (( $(compio_transport_service_metric_value \
    "${metrics_after}" \
    oxibelt_http_compio_direct_h1_connection_events_total \
    event \
    retired_peer_close) < 1 )); then
    fail_with_diagnostics "Connection: close did not record peer-close retirement"
  fi
  if (( $(compio_transport_service_metric_value \
    "${metrics_after}" \
    oxibelt_http_compio_direct_h1_dispatch_total \
    outcome \
    predispatch_fallback) < 2 )); then
    fail_with_diagnostics "bodyful Hyper controls did not record pre-dispatch Compio fallback"
  fi
}
