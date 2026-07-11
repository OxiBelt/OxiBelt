resume_redis_delay() {
  local response
  response="$(docker exec "${redis_container}" sh -ceu '
    if command -v valkey-cli >/dev/null 2>&1; then
      valkey-cli CLIENT UNPAUSE
    else
      redis-cli CLIENT UNPAUSE
    fi
  ')" || return 1
  [[ "${response}" == "OK" ]]
}

run_case_checks() {
  # `CLIENT PAUSE` affects commands issued after this call while leaving the
  # proxy's Tokio worker available to serve health and metrics endpoints. The
  # thirty-second pause is a bounded safety ceiling; the fixture explicitly
  # resumes the backend as soon as all delayed work has drained.
  docker exec "${redis_container}" sh -ceu '
    if command -v valkey-cli >/dev/null 2>&1; then
      valkey-cli CLIENT PAUSE 30000 ALL
    else
      redis-cli CLIENT PAUSE 30000 ALL
    fi
  ' >/dev/null
  source "${repo_root}/tests/scripts/shared-state-delay-isolation-checks.sh"
  run_shared_state_delay_isolation redis resume_redis_delay
}
