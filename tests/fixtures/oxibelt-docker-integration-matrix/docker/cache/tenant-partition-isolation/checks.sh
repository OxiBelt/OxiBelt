
run_case_checks() {
  local path tenant_a tenant_b tenant_a_hit tenant_b_hit
  path="/app/tenant?sequence_key=tenant-partition&body_sequence=tenant-a%7Ctenant-b%7Ctenant-miss&cache_control=public&content_type=text/plain"
  tenant_a="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Tenant-ID: tenant-a")"
  tenant_b="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Tenant-ID: tenant-b")"
  assert_response_jq "${tenant_a}" '.body == "tenant-a"'
  assert_response_jq "${tenant_b}" '.body == "tenant-b"'

  docker rm -f "${http_container}" >/dev/null
  tenant_a_hit="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Tenant-ID: tenant-a")"
  tenant_b_hit="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Tenant-ID: tenant-b")"
  assert_response_jq "${tenant_a_hit}" '.body == "tenant-a"'
  assert_response_jq "${tenant_b_hit}" '.body == "tenant-b"'
}
