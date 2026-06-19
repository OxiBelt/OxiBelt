
run_case_checks() {
  dynamic_policy_status_requires_status_permission
  dynamic_policy_preconditions_reject_missing_and_stale_etags
  create_policy_blocks_after_refresh
  patch_to_dry_run_stops_blocking
  import_upserts_existing_policy
  apply_upserts_policy_without_duplicate_active_rows
  audit_lists_applied_and_rejected_rows
  delete_disables_policy
  tampered_signature_keeps_last_good_snapshot
  default_source_quota_blocks_spoofed_source_rotation
  import_rejects_spoofed_default_source_over_quota
  patch_rejects_enabling_policy_over_default_quota
  global_active_policy_cap_blocks_cross_source_growth
}

wait_for_dynamic_policy_refresh() {
  sleep 3
}

policy_json_field() {
  local response="$1"
  local filter="$2"
  jq -r ".body | fromjson | ${filter}" <<<"${response}"
}

dynamic_policy_etag() {
  local status
  status="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/status" 200 "GET" "" "Authorization: Bearer matrix-security-token")"
  jq -r '.body | fromjson | .etag' <<<"${status}"
}

dynamic_policy_status_requires_status_permission() {
  local response
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/status" 200 "GET" "" "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | fromjson | .etag == "\"oxibelt-dynamic-policy-0\""'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/status" 403 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_response_jq "${response}" '(.body | fromjson) as $body | $body.error.code == "permission_denied" and $body.error.details.action == "dynamic-policy:GetStatus" and $body.error.details.resource == "oxibelt:oxibelt:dynamic-policy:status/current"'
}

dynamic_policy_preconditions_reject_missing_and_stale_etags() {
  local response
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 428 "POST" '{"source":"precondition","name":"missing","action":"reject","subject_type":"client_ip","subject":"203.0.113.59","status":429,"body":"missing etag","reason":"precondition","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | fromjson | .error.message | contains("If-Match is required")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 412 "POST" '{"source":"precondition","name":"stale","action":"reject","subject_type":"client_ip","subject":"203.0.113.58","status":429,"body":"stale etag","reason":"precondition","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token" "If-Match: \"oxibelt-dynamic-policy-stale\"")"
  assert_response_jq "${response}" '.body | fromjson | .error.message | contains("If-Match does not match")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 428 "POST" '{"source":"precondition","name":"invalid-missing","action":"challenge","subject_type":"client_ip","subject":"203.0.113.57","body":"challenge body is invalid","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | fromjson | .error.message | contains("If-Match is required")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 412 "POST" '{"source":"precondition","name":"invalid-stale","action":"challenge","subject_type":"client_ip","subject":"203.0.113.56","body":"challenge body is invalid","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token" "If-Match: \"oxibelt-dynamic-policy-stale\"")"
  assert_response_jq "${response}" '.body | fromjson | .error.message | contains("If-Match does not match")'
}

create_policy_blocks_after_refresh() {
  local response request
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 201 "POST" '{"source":"vaultwarden","name":"failed-login","action":"reject","subject_type":"client_ip_path","subject":"203.0.113.60|/app/identity","path_prefix":"/app/identity","status":429,"body":"automation block","reason":"failed login","code":"vaultwarden.failed_login","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  policy_id="$(policy_json_field "${response}" '.id')"
  assert_response_jq "${response}" '.body | fromjson | .source == "vaultwarden" and .code == "vaultwarden.failed_login" and .mode == "enforce" and .signature_version == "hmac-sha256-v1" and (.row_signature | length) == 64'

  wait_for_dynamic_policy_refresh
  request="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.60")"
  assert_response_jq "${request}" '.body == "automation block"'
}

patch_to_dry_run_stops_blocking() {
  local response request
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/${policy_id}" 200 "PATCH" '{"mode":"dry_run"}' "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  assert_response_jq "${response}" '.body | fromjson | .mode == "dry_run" and .enabled == true'

  wait_for_dynamic_policy_refresh
  request="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.60")"
  assert_body_jq "${request}" '.path == "/origin/app/identity/login"'
}

import_upserts_existing_policy() {
  local response request old_request active_count
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/import" 200 "POST" '{"policies":[{"source":"vaultwarden","name":"failed-login","action":"reject","subject_type":"client_ip_path","subject":"203.0.113.61|/app/identity","path_prefix":"/app/identity","status":429,"body":"import block","reason":"imported failed login","code":"vaultwarden.imported","ttl_seconds":3600}]}' "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  assert_response_jq "${response}" '.body | fromjson | .policies | length == 1'
  imported_policy_id="$(policy_json_field "${response}" '.policies[0].id')"
  if [[ "${imported_policy_id}" != "${policy_id}" ]]; then
    fail_with_diagnostics "import should upsert the existing dynamic policy id"
  fi
  active_count="$(postgres_query "SELECT count(*) FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND source = 'vaultwarden' AND name = 'failed-login' AND enabled = true;")"
  if [[ "${active_count}" != "1" ]]; then
    fail_with_diagnostics "import should leave exactly one active source/name policy"
  fi

  wait_for_dynamic_policy_refresh
  old_request="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.60")"
  assert_body_jq "${old_request}" '.path == "/origin/app/identity/login"'
  request="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.61")"
  assert_response_jq "${request}" '.body == "import block"'
}

apply_upserts_policy_without_duplicate_active_rows() {
  local response request old_request active_count second_policy_id list cursor next bad_cursor
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/apply" 412 "POST" '{"source":"oxibeltctl","name":"panic-login","action":"reject","subject_type":"client_ip_path","subject":"203.0.113.63|/app/identity","path_prefix":"/app/identity","status":429,"body":"apply block stale","reason":"operator panic button","code":"panic.login","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token" "If-Match: \"oxibelt-dynamic-policy-stale\"")"
  assert_response_jq "${response}" '.body | fromjson | .error.message | contains("If-Match does not match")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/apply" 200 "POST" '{"source":"oxibeltctl","name":"panic-login","action":"reject","subject_type":"client_ip_path","subject":"203.0.113.63|/app/identity","path_prefix":"/app/identity","status":429,"body":"apply block v1","reason":"operator panic button","code":"panic.login","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token")"
  apply_policy_id="$(policy_json_field "${response}" '.id')"
  assert_response_jq "${response}" '.body | fromjson | .source == "oxibeltctl" and .name == "panic-login" and .signature_version == "hmac-sha256-v1"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/apply" 200 "POST" '{"source":"oxibeltctl","name":"panic-login","action":"reject","subject_type":"client_ip_path","subject":"203.0.113.64|/app/identity","path_prefix":"/app/identity","status":429,"body":"apply block v2","reason":"operator panic button update","code":"panic.login","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token")"
  second_policy_id="$(policy_json_field "${response}" '.id')"
  if [[ "${second_policy_id}" != "${apply_policy_id}" ]]; then
    fail_with_diagnostics "apply should replace the existing dynamic policy id"
  fi
  active_count="$(postgres_query "SELECT count(*) FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND source = 'oxibeltctl' AND name = 'panic-login' AND enabled = true;")"
  if [[ "${active_count}" != "1" ]]; then
    fail_with_diagnostics "apply should leave exactly one active source/name policy"
  fi

  wait_for_dynamic_policy_refresh
  old_request="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.63")"
  assert_body_jq "${old_request}" '.path == "/origin/app/identity/login"'
  request="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.64")"
  assert_response_jq "${request}" '.body == "apply block v2"'

  list="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies?limit=1&sort=created_at&order=desc&filter%5Benabled%5D=true" 200 "GET" "" "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${list}" '.body | fromjson | .policies | length == 1'
  assert_response_jq "${list}" '.body | fromjson | .pagination.has_more == true and (.pagination.next_cursor | type) == "string" and .pagination.sort == "created_at" and .pagination.order == "desc"'
  cursor="$(policy_json_field "${list}" '.pagination.next_cursor')"
  next="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies?limit=1&sort=created_at&order=desc&filter%5Benabled%5D=true&cursor=${cursor}" 200 "GET" "" "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${next}" '.body | fromjson | .policies | length == 1'
  list="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies?limit=10&filter%5Bsource%5D=oxibeltctl" 200 "GET" "" "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${list}" '.body | fromjson | .policies | all(.source == "oxibeltctl")'
  bad_cursor="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies?limit=1&cursor=not-a-valid-cursor" 400 "GET" "" "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${bad_cursor}" '.body | contains("cursor is invalid")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/${apply_policy_id}" 200 "DELETE" "" "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'
}

audit_lists_applied_and_rejected_rows() {
  local response audit policy_audit
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/apply" 400 "POST" '{"source":"audit-reject","name":"bad-challenge","action":"challenge","subject_type":"client_ip","subject":"203.0.113.65","body":"challenge body is invalid","reason":"invalid challenge","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${response}" '.body | contains("challenge action does not support body")'

  audit="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/audit?limit=50" 200 "GET" "" "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${audit}" '.body | fromjson | .audit | map(select(.operation == "apply" and .outcome == "rejected" and .source == "audit-reject" and .name == "bad-challenge" and (.error | contains("does not support body")))) | length == 1'

  policy_audit="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/audit?limit=20&policy_id=${apply_policy_id}" 200 "GET" "" "Authorization: Bearer matrix-security-token")"
  assert_response_jq "${policy_audit}" ".body | fromjson | .audit | map(select(.policy_id == ${apply_policy_id} and .operation == \"apply\" and .outcome == \"applied\")) | length >= 1"
}

delete_disables_policy() {
  local response request enabled
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/${policy_id}" 200 "DELETE" "" "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'
  enabled="$(postgres_query "SELECT enabled FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND id = ${policy_id};")"
  if [[ "${enabled}" != "f" ]]; then
    fail_with_diagnostics "delete should disable the dynamic policy"
  fi

  wait_for_dynamic_policy_refresh
  request="$(client_request_with_headers "example.test" "/app/identity/login" 200 "GET" "" "X-Forwarded-For: 203.0.113.61")"
  assert_body_jq "${request}" '.path == "/origin/app/identity/login"'
}

tampered_signature_keeps_last_good_snapshot() {
  local response request
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 201 "POST" '{"source":"automation","name":"tamper-check","action":"reject","subject_type":"client_ip","subject":"203.0.113.62","status":429,"body":"signed block","reason":"tamper baseline","code":"tamper.baseline","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  tamper_policy_id="$(policy_json_field "${response}" '.id')"

  wait_for_dynamic_policy_refresh
  request="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.62")"
  assert_response_jq "${request}" '.body == "signed block"'

  postgres_query "UPDATE oxibelt_dynamic_policies SET body = 'tampered block', updated_at = now() WHERE namespace = 'matrix-dynamic-api' AND id = ${tamper_policy_id};" >/dev/null
  postgres_query "INSERT INTO oxibelt_dynamic_policy_generation (namespace, generation, updated_at) VALUES ('matrix-dynamic-api', 1, now()) ON CONFLICT (namespace) DO UPDATE SET generation = oxibelt_dynamic_policy_generation.generation + 1, updated_at = now();" >/dev/null
  wait_for_dynamic_policy_refresh

  request="$(client_request_with_headers "example.test" "/app/identity/login" 429 "GET" "" "X-Forwarded-For: 203.0.113.62")"
  assert_response_jq "${request}" '.body == "signed block"'
}

default_source_quota_blocks_spoofed_source_rotation() {
  local index response body default_bucket_count
  for index in $(seq 1 9); do
    body="{\"source\":\"spoof-${index}\",\"name\":\"spoof-${index}\",\"action\":\"reject\",\"subject_type\":\"client_ip\",\"subject\":\"203.0.113.$((70 + index))\",\"status\":429,\"body\":\"spoof block\",\"reason\":\"spoofed source\",\"code\":\"spoof.${index}\",\"ttl_seconds\":3600}"
    response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 201 "POST" "${body}" "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
    assert_response_jq "${response}" ".body | fromjson | .source == \"spoof-${index}\""
  done

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 400 "POST" '{"source":"spoof-overflow","name":"spoof-overflow","action":"reject","subject_type":"client_ip","subject":"203.0.113.80","status":429,"body":"spoof overflow","reason":"spoofed source","code":"spoof.overflow","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  assert_response_jq "${response}" '.body | contains("default source quota")'

  default_bucket_count="$(postgres_query "SELECT count(*) FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND enabled = true AND (expires_at IS NULL OR expires_at > now()) AND source <> 'vaultwarden';")"
  if [[ "${default_bucket_count}" != "10" ]]; then
    fail_with_diagnostics "default source quota should cap all unconfigured sources together, got ${default_bucket_count}"
  fi
}

import_rejects_spoofed_default_source_over_quota() {
  local response
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/import" 400 "POST" '{"policies":[{"source":"spoof-import","name":"spoof-import","action":"reject","subject_type":"client_ip","subject":"203.0.113.81","status":429,"body":"spoof import","reason":"spoofed import","code":"spoof.import","ttl_seconds":3600}]}' "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  assert_response_jq "${response}" '.body | contains("default source quota")'
}

patch_rejects_enabling_policy_over_default_quota() {
  local response disabled_policy_id enabled
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 201 "POST" '{"enabled":false,"source":"spoof-disabled","name":"spoof-disabled","action":"reject","subject_type":"client_ip","subject":"203.0.113.82","status":429,"body":"spoof disabled","reason":"disabled spoof","code":"spoof.disabled","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  disabled_policy_id="$(policy_json_field "${response}" '.id')"

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies/${disabled_policy_id}" 400 "PATCH" '{"enabled":true}' "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  assert_response_jq "${response}" '.body | contains("default source quota")'

  enabled="$(postgres_query "SELECT enabled FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND id = ${disabled_policy_id};")"
  if [[ "${enabled}" != "f" ]]; then
    fail_with_diagnostics "patch over default source quota must leave the policy disabled"
  fi
}

global_active_policy_cap_blocks_cross_source_growth() {
  local index response body active_total
  for index in $(seq 1 2); do
    body="{\"source\":\"vaultwarden\",\"name\":\"global-cap-${index}\",\"action\":\"reject\",\"subject_type\":\"client_ip\",\"subject\":\"203.0.113.$((90 + index))\",\"status\":429,\"body\":\"global cap\",\"reason\":\"global cap\",\"code\":\"global.cap.${index}\",\"ttl_seconds\":3600}"
    response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 201 "POST" "${body}" "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
    assert_response_jq "${response}" ".body | fromjson | .source == \"vaultwarden\" and .name == \"global-cap-${index}\""
  done

  active_total="$(postgres_query "SELECT count(*) FROM oxibelt_dynamic_policies WHERE namespace = 'matrix-dynamic-api' AND enabled = true AND (expires_at IS NULL OR expires_at > now());")"
  if [[ "${active_total}" != "12" ]]; then
    fail_with_diagnostics "expected active policy count to reach max_policies before overflow, got ${active_total}"
  fi

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/dynamic-policies" 400 "POST" '{"source":"vaultwarden","name":"global-cap-overflow","action":"reject","subject_type":"client_ip","subject":"203.0.113.93","status":429,"body":"global cap overflow","reason":"global cap","code":"global.cap.overflow","ttl_seconds":3600}' "Authorization: Bearer matrix-security-token" "If-Match: $(dynamic_policy_etag)")"
  assert_response_jq "${response}" '.body | contains("max_policies")'
}
