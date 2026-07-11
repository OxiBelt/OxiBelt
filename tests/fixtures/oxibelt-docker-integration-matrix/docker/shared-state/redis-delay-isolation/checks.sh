run_case_checks() {
  # `CLIENT PAUSE` affects commands issued after this call while leaving the
  # proxy's Tokio worker available to serve health and metrics endpoints.
  docker exec "${redis_container}" sh -ceu '
    if command -v valkey-cli >/dev/null 2>&1; then
      valkey-cli CLIENT PAUSE 3000 ALL
    else
      redis-cli CLIENT PAUSE 3000 ALL
    fi
  ' >/dev/null
  source "${repo_root}/tests/scripts/shared-state-delay-isolation-checks.sh"
  run_shared_state_delay_isolation redis
}
