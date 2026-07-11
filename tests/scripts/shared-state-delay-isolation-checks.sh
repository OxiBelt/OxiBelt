#!/usr/bin/env bash
# Shared helpers for deterministic, rootless Docker shared-state delay tests.
# This file is sourced by the Docker integration matrix after it has created
# the isolated network and helper containers.

shared_state_delay_probe() {
  local port="$1"
  local host="$2"
  local path="$3"
  docker exec "${http_container}" \
    python /opt/mock_upstream/client.py \
    --scheme http \
    --target-host proxy \
    --port "${port}" \
    --host "${host}" \
    --path "${path}" \
    --method GET \
    --body "" \
    --timeout 1 \
    --dump-response-json \
    --expect-status 200
}

shared_state_delay_metric_value() {
  local response="$1"
  local metric="$2"
  local backend_kind="$3"
  local state="${4:-}"
  jq -r '.body' <<<"${response}" | awk -v metric="${metric}" -v kind="${backend_kind}" -v state="${state}" '
    index($1, metric "{") == 1 && index($0, "backend=\"cluster\"") && index($0, "kind=\"" kind "\"") && (state == "" || index($0, "state=\"" state "\"")) {
      value = $NF
    }
    END {
      if (value == "") {
        exit 1
      }
      print value
    }
  '
}

shared_state_delay_timeout_metric_present() {
  local response="$1"
  local metric="$2"
  local backend_kind="$3"
  # A saturated backend can time out either inside the logical operation or
  # while acquiring its bounded pool slot. Both are intentional, measured
  # shared-state timeout boundaries for this backend.
  jq -r '.body' <<<"${response}" | grep -F "${metric}" | grep -F 'backend="cluster"' | grep -F "kind=\"${backend_kind}\"" | grep -F 'outcome="timeout"' >/dev/null
}

shared_state_delay_launch_requests() {
  local output_path="$1"
  docker exec "${http_container}" sh -ceu '
    pids=""
    failures=0
    for i in $(seq 1 16); do
      (
        if output="$(python /opt/mock_upstream/client.py \
          --scheme http \
          --target-host proxy \
          --port 8080 \
          --host example.test \
          --path /app/delay \
          --method GET \
          --body "" \
          --header "X-Forwarded-For: 198.51.100.${i}" \
          --header "X-Delay-Sentinel: delay-secret-do-not-export" \
          --timeout 6 \
          --dump-response-json \
          --expect-status 503 2>&1)"; then
          printf "%s\\n" "${output}"
          exit 0
        else
          status=$?
        fi
        printf "%s\\n" "${output}"
        # Shared connection admission runs before HTTP parsing. Its configured
        # 503 therefore closes the downstream TCP connection instead of writing
        # an HTTP response. Depending on whether the close reaches the client
        # while sending or receiving, Python reports an exact broken pipe,
        # connection reset, or response EOF. Normalize only those controlled
        # fail-closed outcomes so unrelated network failures remain rejected.
        if [ "${status}" -ne 0 ]; then
          case "${output}" in
            "[Errno 32] Broken pipe"|"[Errno 104] Connection reset by peer"|"Remote end closed connection without response")
              printf "%s\\n" "shared-state-delay-controlled-pre-response-close"
              exit 0
              ;;
          esac
        fi
        exit 1
      ) &
      pids="${pids} $!"
    done
    for pid in ${pids}; do
      if ! wait "${pid}"; then
        failures=1
      fi
    done
    exit "${failures}"
  ' >"${output_path}" 2>&1 &
  SHARED_STATE_DELAY_REQUEST_PID=$!
}

shared_state_delay_wait_for_requests() {
  local output_path="$1"
  if ! wait "${SHARED_STATE_DELAY_REQUEST_PID}"; then
    cat "${output_path}" >&2 || true
    fail_with_diagnostics "delayed shared-state requests did not fail closed"
  fi
  local count
  count="$(grep -Ec '"status": 503|^shared-state-delay-controlled-pre-response-close$' "${output_path}" || true)"
  if [[ "${count}" != "16" ]]; then
    cat "${output_path}" >&2 || true
    fail_with_diagnostics "expected sixteen bounded shared-state timeout rejections, got ${count}"
  fi
}

shared_state_delay_assert_metrics_during_delay() {
  local response="$1"
  local backend_kind="$2"
  if [[ "${backend_kind}" == "redis" ]]; then
    local waiting active
    waiting="$(shared_state_delay_metric_value "${response}" oxibelt_shared_state_pool_waiters "${backend_kind}")" || fail_with_diagnostics "missing Redis pool waiter gauge during backend delay"
    active="$(shared_state_delay_metric_value "${response}" oxibelt_shared_state_pool_connections "${backend_kind}" active)" || fail_with_diagnostics "missing Redis pool active-connection gauge during backend delay"
    if (( waiting <= 0 || active <= 0 )); then
      jq -r '.body' <<<"${response}" >&2
      fail_with_diagnostics "expected queued Redis pool work and an active Redis connection during backend delay"
    fi
    if jq -r '.body' <<<"${response}" | grep -F 'delay-secret-do-not-export' >/dev/null; then
      fail_with_diagnostics "shared-state metric labels exposed request data"
    fi
    return
  fi
  local queued in_flight
  queued="$(shared_state_delay_metric_value "${response}" oxibelt_shared_state_queued_operations "${backend_kind}")" || fail_with_diagnostics "missing shared-state queued gauge during backend delay"
  in_flight="$(shared_state_delay_metric_value "${response}" oxibelt_shared_state_in_flight_operations "${backend_kind}")" || fail_with_diagnostics "missing shared-state in-flight gauge during backend delay"
  if (( queued <= 0 || in_flight <= 0 )); then
    jq -r '.body' <<<"${response}" >&2
    fail_with_diagnostics "expected positive queued and in-flight shared-state gauges during backend delay"
  fi
  if ! shared_state_delay_timeout_metric_present "${response}" oxibelt_shared_state_operation_duration_ms_count "${backend_kind}" && ! shared_state_delay_timeout_metric_present "${response}" oxibelt_shared_state_queue_duration_ms_count "${backend_kind}"; then
    # The first in-flight timeout and queued timeouts are recorded after the
    # delay; this branch only checks that the bounded metric family is present.
    jq -r '.body' <<<"${response}" | grep -F 'oxibelt_shared_state_' >/dev/null || fail_with_diagnostics "missing shared-state metric family during backend delay"
  fi
  if jq -r '.body' <<<"${response}" | grep -F 'delay-secret-do-not-export' >/dev/null; then
    fail_with_diagnostics "shared-state metric labels exposed request data"
  fi
}

shared_state_delay_metrics_are_positive() {
  local response="$1"
  local backend_kind="$2"
  if [[ "${backend_kind}" == "redis" ]]; then
    local waiting active
    waiting="$(shared_state_delay_metric_value "${response}" oxibelt_shared_state_pool_waiters "${backend_kind}")" || return 1
    active="$(shared_state_delay_metric_value "${response}" oxibelt_shared_state_pool_connections "${backend_kind}" active)" || return 1
    (( waiting > 0 && active > 0 ))
    return
  fi
  local queued in_flight
  queued="$(shared_state_delay_metric_value "${response}" oxibelt_shared_state_queued_operations "${backend_kind}")" || return 1
  in_flight="$(shared_state_delay_metric_value "${response}" oxibelt_shared_state_in_flight_operations "${backend_kind}")" || return 1
  (( queued > 0 && in_flight > 0 ))
}

shared_state_delay_assert_post_delay_metrics() {
  local backend_kind="$1"
  local metrics=""
  local queued=""
  local in_flight=""
  local attempt
  for attempt in $(seq 1 20); do
    metrics="$(shared_state_delay_probe 9090 ops.test /metrics)" || fail_with_diagnostics "metrics endpoint did not remain responsive after backend delay"
    if [[ "${backend_kind}" == "redis" ]]; then
      queued="$(shared_state_delay_metric_value "${metrics}" oxibelt_shared_state_pool_waiters "${backend_kind}")" || true
      in_flight="$(shared_state_delay_metric_value "${metrics}" oxibelt_shared_state_pool_connections "${backend_kind}" active)" || true
      if [[ "${queued}" == "0" && "${in_flight}" == "0" ]]; then
        if ! shared_state_delay_timeout_metric_present "${metrics}" oxibelt_shared_state_operation_duration_ms_count "${backend_kind}"; then
          jq -r '.body' <<<"${metrics}" >&2
          fail_with_diagnostics "expected bounded shared-state timeout metric after Redis delay"
        fi
        if jq -r '.body' <<<"${metrics}" | grep -F 'delay-secret-do-not-export' >/dev/null; then
          fail_with_diagnostics "shared-state metric labels exposed request data"
        fi
        return
      fi
      sleep 0.1
      continue
    fi
    queued="$(shared_state_delay_metric_value "${metrics}" oxibelt_shared_state_queued_operations "${backend_kind}")" || true
    in_flight="$(shared_state_delay_metric_value "${metrics}" oxibelt_shared_state_in_flight_operations "${backend_kind}")" || true
    if [[ "${queued}" == "0" && "${in_flight}" == "0" ]]; then
      if ! shared_state_delay_timeout_metric_present "${metrics}" oxibelt_shared_state_operation_duration_ms_count "${backend_kind}" && ! shared_state_delay_timeout_metric_present "${metrics}" oxibelt_shared_state_queue_duration_ms_count "${backend_kind}"; then
        jq -r '.body' <<<"${metrics}" >&2
        fail_with_diagnostics "expected bounded shared-state timeout metric after backend delay"
      fi
      if jq -r '.body' <<<"${metrics}" | grep -F 'delay-secret-do-not-export' >/dev/null; then
        fail_with_diagnostics "shared-state metric labels exposed request data"
      fi
      return
    fi
    sleep 0.1
  done
  jq -r '.body' <<<"${metrics}" >&2
  fail_with_diagnostics "shared-state gauges did not return to zero after timed-out work"
}

shared_state_delay_assert_recovery() {
  local response=""
  local attempt
  for attempt in $(seq 1 10); do
    if response="$(docker exec "${http_container}" python /opt/mock_upstream/client.py --scheme http --target-host proxy --port 8080 --host example.test --path /app/delay --method GET --body "" --header 'X-Forwarded-For: 198.51.100.250' --timeout 1 --dump-response-json --expect-status 200)"; then
      if jq -e '.body | contains("/origin/app/delay")' <<<"${response}" >/dev/null; then
        return
      fi
    fi
    sleep 0.1
  done
  echo "${response}" >&2
  fail_with_diagnostics "fresh request did not recover after shared-state backend delay"
}

shared_state_delay_resume_backend() {
  local resume_callback="$1"
  if ! declare -F "${resume_callback}" >/dev/null; then
    fail_with_diagnostics "shared-state backend resume callback is not defined: ${resume_callback}"
  fi
  if ! "${resume_callback}"; then
    fail_with_diagnostics "failed to resume shared-state backend after delayed work"
  fi
}

run_shared_state_delay_isolation() {
  local backend_kind="$1"
  local resume_callback="${2:-}"
  local resume_phase="${3:-after_post_delay_metrics}"
  local delayed_requests_log="${logs_dir}/shared-state-delay-${backend_kind}.jsonl"
  local live_response metrics_response
  local attempt

  case "${resume_phase}" in
    before_post_delay_metrics|after_post_delay_metrics) ;;
    *) fail_with_diagnostics "unsupported shared-state backend resume phase: ${resume_phase}" ;;
  esac

  shared_state_delay_launch_requests "${delayed_requests_log}"
  for attempt in $(seq 1 10); do
    live_response="$(shared_state_delay_probe 9091 ops.test /live)" || fail_with_diagnostics "live endpoint blocked behind shared-state backend work"
    jq -e '.body == "live"' <<<"${live_response}" >/dev/null || fail_with_diagnostics "live endpoint returned an unexpected response during backend delay"
    metrics_response="$(shared_state_delay_probe 9090 ops.test /metrics)" || fail_with_diagnostics "metrics endpoint blocked behind shared-state backend work"
    if shared_state_delay_metrics_are_positive "${metrics_response}" "${backend_kind}"; then
      break
    fi
    sleep 0.1
  done
  shared_state_delay_assert_metrics_during_delay "${metrics_response}" "${backend_kind}"
  shared_state_delay_wait_for_requests "${delayed_requests_log}"
  if [[ -n "${resume_callback}" && "${resume_phase}" == "before_post_delay_metrics" ]]; then
    shared_state_delay_resume_backend "${resume_callback}"
  fi
  shared_state_delay_assert_post_delay_metrics "${backend_kind}"
  if [[ -n "${resume_callback}" && "${resume_phase}" == "after_post_delay_metrics" ]]; then
    shared_state_delay_resume_backend "${resume_callback}"
  fi
  shared_state_delay_assert_recovery
}
