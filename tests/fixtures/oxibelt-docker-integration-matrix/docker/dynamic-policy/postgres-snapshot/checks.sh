
run_case_checks() {
  seed_dynamic_policy_reject
  wait_for_dynamic_policy_refresh
  assert_dynamic_policy_rejects_path
  assert_expired_policy_passes
  assert_route_mismatch_passes
  assert_dynamic_asn_route_policy
  assert_dynamic_rate_limit
  assert_noncanonical_ipv6_dynamic_policies
  assert_refresh_failure_keeps_last_good
  assert_dynamic_policies_use_dedicated_table
}

bump_dynamic_policy_generation() {
  postgres_query "INSERT INTO oxibelt_dynamic_policy_generation (namespace, generation, updated_at) VALUES ('matrix-dynamic', 1, now()) ON CONFLICT (namespace) DO UPDATE SET generation = oxibelt_dynamic_policy_generation.generation + 1, updated_at = now();" >/dev/null
}

wait_for_dynamic_policy_refresh() {
  sleep 3
}

seed_dynamic_policy_reject() {
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, path_prefix, status, body, reason) VALUES ('matrix-dynamic', 10, 'vaultwarden-block', 'reject', 'client_ip_path', '203.0.113.50|/app/identity', '/app/identity', 429, 'vaultwarden dynamic block', 'vaultwarden failed-login TTL block');" >/dev/null
  bump_dynamic_policy_generation
}

assert_dynamic_policy_rejects_path() {
  local response
  response="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.50")"
  assert_response_jq "${response}" '.body == "vaultwarden dynamic block"'
}

assert_expired_policy_passes() {
  local response
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, path_prefix, status, body, expires_at) VALUES ('matrix-dynamic', 20, 'expired-block', 'reject', 'client_ip_path', '203.0.113.51|/app/identity', '/app/identity', 429, 'expired block', now() - interval '1 second');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh
  response="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.51")"
  assert_body_jq "${response}" '.path == "/origin/app/identity/login"'
}

assert_route_mismatch_passes() {
  local response
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, route_name, status, body) VALUES ('matrix-dynamic', 30, 'admin-only-block', 'reject', 'client_ip_route', '203.0.113.53|admin-route', 'admin-route', 429, 'admin block');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh
  response="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.53")"
  assert_body_jq "${response}" '.path == "/origin/app/identity/login"'
}

assert_dynamic_asn_route_policy() {
  local blocked passed
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, route_name, status, body) VALUES ('matrix-dynamic', 35, 'asn-route-block', 'reject', 'asn_route', 'AS64500|app-route', 'app-route', 429, 'asn route block');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh
  blocked="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.54")"
  assert_response_jq "${blocked}" '.body == "asn route block"'
  passed="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.114.54")"
  assert_body_jq "${passed}" '.path == "/origin/app/identity/login"'
}

assert_dynamic_rate_limit() {
  local first second
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, rate, burst, status, body) VALUES ('matrix-dynamic', 40, 'dynamic-login-rate', 'rate_limit', 'client_ip', '203.0.113.52', '1r/h', 1, 429, 'dynamic rate limited');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh
  first="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.52")"
  assert_body_jq "${first}" '.path == "/origin/app/identity/login"'
  second="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.52")"
  assert_response_jq "${second}" '.body == "dynamic rate limited"'
}

assert_noncanonical_ipv6_dynamic_policies() {
  local path_response route_response first second
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, path_prefix, status, body) VALUES ('matrix-dynamic', 41, 'ipv6-path-block', 'reject', 'client_ip_path', '2001:0DB8:0000:0000:0000:0000:0000:0001|/app/identity', '/app/identity', 429, 'ipv6 path block');" >/dev/null
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, route_name, status, body) VALUES ('matrix-dynamic', 42, 'ipv6-route-block', 'reject', 'client_ip_route', '2001:0DB8:0000:0000:0000:0000:0000:0002|app-route', 'app-route', 429, 'ipv6 route block');" >/dev/null
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, rate, burst, status, body) VALUES ('matrix-dynamic', 43, 'ipv6-client-rate', 'rate_limit', 'client_ip', '2001:0DB8:0000:0000:0000:0000:0000:0003', '1r/h', 1, 429, 'ipv6 rate limited');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh

  path_response="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 2001:db8::1")"
  assert_response_jq "${path_response}" '.body == "ipv6 path block"'

  route_response="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 2001:db8::2")"
  assert_response_jq "${route_response}" '.body == "ipv6 route block"'

  first="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 2001:db8::3")"
  assert_body_jq "${first}" '.path == "/origin/app/identity/login"'
  second="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 2001:db8::3")"
  assert_response_jq "${second}" '.body == "ipv6 rate limited"'
}

assert_refresh_failure_keeps_last_good() {
  local response
  postgres_query "INSERT INTO oxibelt_dynamic_policies (namespace, priority, name, action, subject_type, subject, status, body) VALUES ('matrix-dynamic', 5, 'invalid-active-policy', 'reject', 'client_ip', 'not-an-ip', 429, 'invalid');" >/dev/null
  bump_dynamic_policy_generation
  wait_for_dynamic_policy_refresh
  response="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.50")"
  assert_response_jq "${response}" '.body == "vaultwarden dynamic block"'
}

assert_dynamic_policies_use_dedicated_table() {
  local policy_count shared_policy_count
  policy_count="$(postgres_query "SELECT count(*) FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic';")"
  if (( policy_count < 4 )); then
    fail_with_diagnostics "expected dynamic policies in dedicated table, got ${policy_count}"
  fi
  shared_policy_count="$(postgres_query "SELECT count(*) FROM oxibelt_shared_state WHERE key LIKE '%vaultwarden-block%';")"
  if [[ "${shared_policy_count}" != "0" ]]; then
    fail_with_diagnostics "dynamic policy rows must not be stored in oxibelt_shared_state"
  fi
}
