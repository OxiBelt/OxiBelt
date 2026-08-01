
admin_config_etag() {
  local status
  status="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/status" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  jq -r '.body | fromjson | .etag' <<<"${status}"
}

run_case_checks() {
  local response raw_config validate_body loaded_config load_body guessed_secret_config guessed_secret_body
  local legacy_matching legacy_mismatching etag synced_group sync_body bad_body

  response="$(client_request "example.test" "/app/admin-before" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/admin-before"'

  response="$(client_request "example.test" "/app/admin-synced" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/admin-synced"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/status" 200 "GET" "" "Authorization: Bearer matrix-upstream-token")"
  assert_response_jq "${response}" '.body | fromjson | .revision == 1'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/effective" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body | fromjson | .config | contains("[admin]")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/effective" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_response_jq "${response}" '.body | fromjson | .config | contains("rest_shared_secret = \"<redacted>\"")'
  assert_response_jq "${response}" '.body | fromjson | .config | contains("password = \"<redacted>\"")'
  assert_response_jq "${response}" '(.body | fromjson | .config | contains("REST-SHARED-SECRET-LEAK")) | not'
  assert_response_jq "${response}" '(.body | fromjson | .config | contains("STATIC-PASSWORD-LEAK")) | not'

  raw_config="$(docker exec "${proxy_container}" cat /etc/oxibelt/config/oxibelt.toml)"
  validate_body="$(jq -cn --arg config "${raw_config}" '{format:"toml",config:$config}')"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/validate" 200 "POST" "${validate_body}" "Authorization: Bearer matrix-upstream-token")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  loaded_config="${raw_config}"$'\n\n'
  loaded_config+="$(cat <<'TOML'
[[waf.rules]]
name = "admin-runtime-block"
phase = "request"
priority = 20
when = "Request.Http.Path == '/app/admin-loaded'"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "loaded config"
TOML
)"
  load_body="$(jq -cn --arg config "${loaded_config}" '{format:"toml",config:$config}')"

  guessed_secret_config="${loaded_config/REST-SHARED-SECRET-LEAK/GUESSED-REST-SHARED-SECRET}"
  guessed_secret_body="$(jq -cn --arg config "${guessed_secret_config}" '{format:"toml",config:$config}')"

  legacy_matching="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/diff" 403 "POST" "${load_body}" "Authorization: Bearer matrix-upstream-token")"
  legacy_mismatching="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/diff" 403 "POST" "${guessed_secret_body}" "Authorization: Bearer matrix-upstream-token")"
  assert_response_jq "${legacy_matching}" '(.body | fromjson) as $body | $body.error.code == "permission_denied" and $body.error.message == "forbidden" and $body.error.details.action == "config:DiffSecrets" and $body.error.details.resource == "oxibelt:oxibelt:config:*"'
  assert_response_jq "${legacy_mismatching}" '(.body | fromjson) as $body | $body.error.code == "permission_denied" and $body.error.message == "forbidden" and $body.error.details.action == "config:DiffSecrets" and $body.error.details.resource == "oxibelt:oxibelt:config:*"'
  if [[ "$(jq -c '.body | fromjson | del(.request_id)' <<<"${legacy_matching}")" != "$(jq -c '.body | fromjson | del(.request_id)' <<<"${legacy_mismatching}")" ]]; then
    fail_with_diagnostics "legacy config:Diff responses exposed secret equality"
  fi

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/diff" 200 "POST" "${guessed_secret_body}" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '(.body | fromjson) as $body | $body.activation_plan_schema_version == 3 and any($body.changes[]; .path == "webrtc_turn_listeners[0].auth.rest_shared_secret" and .secret == true and (has("current_value") | not) and (has("candidate_value") | not))'
  assert_response_jq "${response}" '(.body | contains("GUESSED-REST-SHARED-SECRET")) | not'

  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/load" 403 "POST" "${load_body}" "Authorization: Bearer matrix-upstream-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '(.body | fromjson) as $body | $body.error.code == "permission_denied" and $body.error.message == "forbidden" and $body.error.details.action == "config:Load"'

  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/load" 200 "POST" "${load_body}" "Authorization: Bearer matrix-admin-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  response="$(client_request "example.test" "/app/admin-loaded" 403)"
  assert_response_jq "${response}" '.body == "loaded config"'

  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/rollback" 200 "POST" "" "Authorization: Bearer matrix-admin-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'

  response="$(client_request "example.test" "/app/admin-loaded" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/admin-loaded"'

  docker exec --user root "${proxy_container}" chown -R oxibelt:oxibelt /etc/oxibelt/config /etc/oxibelt/oxirule

  synced_group="$(cat <<'TOML'
[[rule_groups]]
name = "synced-block"
when = "Request.Http.Path == '/app/admin-synced'"
TOML
)"
  sync_body="$(jq -cn --arg content "${synced_group}" '{apply:"oxirule",operations:[{op:"put",root:"oxirule_group",path:"groups/admin.oxirule-group.toml",content:$content}]}')"
  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/files/sync" 200 "POST" "${sync_body}" "Authorization: Bearer matrix-admin-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true and .operations == 1'

  response="$(client_request "example.test" "/app/admin-synced" 403)"
  assert_response_jq "${response}" '.body == "synced group"'

  docker exec "${proxy_container}" test -f /etc/oxibelt/oxirule/groups/admin.oxirule-group.toml

  bad_body="$(jq -cn --arg content "[section]\n" '{apply:"none",operations:[{op:"put",root:"config",path:"bad-sync.toml",expected_sha256:"0000000000000000000000000000000000000000000000000000000000000000",content:$content}]}')"
  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/files/sync" 400 "POST" "${bad_body}" "Authorization: Bearer matrix-admin-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body | fromjson | .error.message | contains("expected_sha256")'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/status" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body | fromjson | .last_operation.operation == "files_sync" and .last_operation.outcome == "rejected"'

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/tls/downstream" 200 "GET" "" "Authorization: Bearer matrix-viewer-token")"
  assert_response_jq "${response}" '.body | fromjson | .private_key_configured == true'

  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/tls/downstream/reload" 403 "POST" "" "Authorization: Bearer matrix-viewer-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '(.body | fromjson) as $body | $body.error.code == "permission_denied" and $body.error.message == "forbidden" and $body.error.details.action == "config:ReloadDownstreamTls"'

  etag="$(admin_config_etag)"
  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/tls/downstream/reload" 200 "POST" "" "Authorization: Bearer matrix-admin-token" "If-Match: ${etag}")"
  assert_response_jq "${response}" '.body | fromjson | .ok == true'
}
