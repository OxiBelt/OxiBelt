
run_case_checks() {
  local path seed revalidated
  path="/no-bg/shared-stale?sequence_key=no-bg-shared-disabled&body_sequence=old%7Cnew&cache_control_value=public%2C%20max-age%3D1%2C%20stale-while-revalidate%3D30%2C%20stale-if-error%3D30&last_modified=Wed%2C%2021%20Oct%202015%2007%3A28%3A00%20GMT&content_type=text/plain"

  seed="$(client_request_with_headers "example.test" "${path}" 200 "GET" "")"
  assert_response_jq "${seed}" '.body == "old"'
  assert_response_jq "${seed}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'

  sleep 2

  revalidated="$(client_request_with_headers_to_target "proxy-b" 8443 "example.test" "${path}" 200 "GET" "")"
  assert_response_jq "${revalidated}" '.body == "old"'
  assert_response_jq "${revalidated}" '.headers["x-oxibelt-cache"] == "revalidated" and .headers["x-oxibelt-cache-reason"] == "not_modified"'
}
