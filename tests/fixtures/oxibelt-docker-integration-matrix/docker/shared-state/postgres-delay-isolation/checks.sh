postgres_delay_application_name=""
postgres_delay_lock_log=""
postgres_delay_lock_pid=""

postgres_delay_session_count() {
  postgres_query "SELECT count(*) FROM pg_stat_activity WHERE application_name = '${postgres_delay_application_name}';"
}

postgres_delay_granted_lock_count() {
  postgres_query "SELECT count(*) FROM pg_stat_activity AS activity WHERE activity.application_name = '${postgres_delay_application_name}' AND EXISTS (SELECT 1 FROM pg_locks AS held_lock WHERE held_lock.pid = activity.pid AND held_lock.relation = 'oxibelt_shared_rate_buckets'::regclass AND held_lock.mode = 'AccessExclusiveLock' AND held_lock.granted);"
}

resume_postgres_delay() {
  local cancel_result=""
  local lock_count="1"
  local lock_status=0
  local session_count="1"
  local attempt

  cancel_result="$(postgres_query "SELECT pg_cancel_backend(activity.pid) FROM pg_stat_activity AS activity WHERE activity.application_name = '${postgres_delay_application_name}' AND activity.pid <> pg_backend_pid() AND EXISTS (SELECT 1 FROM pg_locks AS held_lock WHERE held_lock.pid = activity.pid AND held_lock.relation = 'oxibelt_shared_rate_buckets'::regclass AND held_lock.mode = 'AccessExclusiveLock' AND held_lock.granted);")" || return 1
  if [[ "${cancel_result}" != "t" ]]; then
    echo "expected to cancel exactly one PostgreSQL delay lock session, got: ${cancel_result}" >&2
    return 1
  fi

  wait "${postgres_delay_lock_pid}" || lock_status=$?
  if [[ "${lock_status}" == "0" ]]; then
    echo "PostgreSQL delay lock completed before controlled cancellation" >&2
    return 1
  fi
  if ! grep -F "canceling statement due to user request" "${postgres_delay_lock_log}" >/dev/null; then
    cat "${postgres_delay_lock_log}" >&2 || true
    echo "PostgreSQL delay lock did not exit through the expected cancellation" >&2
    return 1
  fi

  for attempt in $(seq 1 30); do
    session_count="$(postgres_delay_session_count)" || return 1
    lock_count="$(postgres_delay_granted_lock_count)" || return 1
    if [[ "${session_count}" == "0" && "${lock_count}" == "0" ]]; then
      return 0
    fi
    sleep 0.1
  done

  echo "PostgreSQL delay lock session remained after controlled cancellation" >&2
  return 1
}

run_case_checks() {
  local lock_count="0"
  local attempt

  postgres_delay_application_name="oxibelt-delay-lock-${run_id}"
  postgres_delay_lock_log="${logs_dir}/postgres-delay-lock.log"

  # Hold the exact rate-bucket table until the shared helper has observed all
  # bounded timeout outcomes. The sleep is only a safety ceiling; the resume
  # callback cancels this uniquely named session before the recovery probe.
  docker exec \
    -e PGPASSWORD=oxibelt \
    -e PGAPPNAME="${postgres_delay_application_name}" \
    "${postgres_container}" \
    sh -ceu '
      psql -v ON_ERROR_STOP=1 -U oxibelt -d oxibelt -c "BEGIN; LOCK TABLE oxibelt_shared_rate_buckets IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(30); COMMIT;"
    ' >"${postgres_delay_lock_log}" 2>&1 &
  postgres_delay_lock_pid=$!
  for attempt in $(seq 1 30); do
    lock_count="$(postgres_delay_granted_lock_count)"
    if [[ "${lock_count}" == "1" ]]; then
      break
    fi
    sleep 0.1
  done
  if [[ "${lock_count}" != "1" ]]; then
    cat "${postgres_delay_lock_log}" >&2 || true
    wait "${postgres_delay_lock_pid}" || true
    fail_with_diagnostics "PostgreSQL delay lock was not granted before the request load"
  fi

  source "${repo_root}/tests/scripts/shared-state-delay-isolation-checks.sh"
  run_shared_state_delay_isolation postgres resume_postgres_delay before_post_delay_metrics
}
