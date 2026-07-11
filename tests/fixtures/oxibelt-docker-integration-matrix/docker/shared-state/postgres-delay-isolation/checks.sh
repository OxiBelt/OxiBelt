run_case_checks() {
  local lock_log="${logs_dir}/postgres-delay-lock.log"
  local lock_count="0"
  local attempt

  # Hold the exact rate-bucket table the request path updates, then verify the
  # lock is granted before producing concurrent backend-bound requests.
  docker exec -e PGPASSWORD=oxibelt "${postgres_container}" sh -ceu '
    psql -v ON_ERROR_STOP=1 -U oxibelt -d oxibelt -c "BEGIN; LOCK TABLE oxibelt_shared_rate_buckets IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(3); COMMIT;"
  ' >"${lock_log}" 2>&1 &
  local lock_pid=$!
  for attempt in $(seq 1 30); do
    lock_count="$(postgres_query "SELECT count(*) FROM pg_locks WHERE relation = 'oxibelt_shared_rate_buckets'::regclass AND mode = 'AccessExclusiveLock' AND granted;")"
    if [[ "${lock_count}" == "1" ]]; then
      break
    fi
    sleep 0.1
  done
  if [[ "${lock_count}" != "1" ]]; then
    cat "${lock_log}" >&2 || true
    wait "${lock_pid}" || true
    fail_with_diagnostics "PostgreSQL delay lock was not granted before the request load"
  fi

  source "${repo_root}/tests/scripts/shared-state-delay-isolation-checks.sh"
  run_shared_state_delay_isolation postgres
  if ! wait "${lock_pid}"; then
    cat "${lock_log}" >&2 || true
    fail_with_diagnostics "PostgreSQL delay lock command failed"
  fi
}
