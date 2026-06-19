
run_case_checks() {
  local path response purge logs audit_logs
  path="/app/audit-purge?cache_control=public&token=raw-secret-not-for-audit"
  response="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'
  purge="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/audit-purge%3Fcache_control%3Dpublic%26token%3Draw-secret-not-for-audit" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${purge}" '.body == "purged=2\n"'
  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  audit_logs="$(grep -F 'oxibelt.admin.audit' <<<"${logs}" || true)"
  if ! grep -F 'cache_purge' <<<"${audit_logs}" | grep -F 'applied' >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "cache purge audit event was not emitted"
  fi
  if ! grep -F 'service' <<<"${audit_logs}" | grep -F 'cache' >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "cache purge authorization audit did not record service=cache"
  fi
  if grep -F 'raw-secret-not-for-audit' <<<"${audit_logs}" >/dev/null; then
    echo "${audit_logs}" >&2
    fail_with_diagnostics "cache purge audit leaked raw URI query value"
  fi
}
