
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/revalidate?etag=matrix-v1&cache_control=public" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'

  response="$(client_request_with_headers "example.test" "/app/revalidate?etag=matrix-v1&cache_control=public" 200 "GET" "" "Cache-Control: no-cache")"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/revalidate?etag=matrix-v1&cache_control=public"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "revalidated" and .headers["x-oxibelt-cache-reason"] == "not_modified"'
}
