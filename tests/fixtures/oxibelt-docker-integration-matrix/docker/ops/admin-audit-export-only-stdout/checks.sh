run_case_checks() {
  local response logs

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/config/status" 200 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body | fromjson | .revision == 1'

  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  if ! jq -R -s -e '
    [split("\n")[] | fromjson?]
    | any(.[]; .class_uid == 6003
      and .unmapped.oxibelt.scope == "admin"
      and .unmapped.oxibelt.path == "/admin/v1/config/status"
      and .unmapped.oxibelt.status == 200)
  ' <<<"${logs}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected Admin audit OCSF JSON on stdout"
  fi

  response="$(plain_client_request_with_headers_on_port 9092 "proxy" "/admin/v1/audit" 409 "GET" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${response}" '.body | contains("admin audit store is not configured")'
}
