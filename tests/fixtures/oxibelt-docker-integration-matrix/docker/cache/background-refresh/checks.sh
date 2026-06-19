
run_case_checks() {
  local first stale second_stale refreshed
  first="$(client_request "example.test" "/app/bg?sequence_key=bg-refresh&body_sequence=old%7Cold%7Cnew&cache_control=public-stale-revalidate&content_type=text/plain" 200)"
  assert_response_jq "${first}" '.body == "old"'
  assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'
  sleep 2
  stale="$(client_request "example.test" "/app/bg?sequence_key=bg-refresh&body_sequence=old%7Cold%7Cnew&cache_control=public-stale-revalidate&content_type=text/plain" 200)"
  assert_response_jq "${stale}" '.body == "old"'
  assert_response_jq "${stale}" '(.headers["x-oxibelt-cache"] == "stale" and .headers["x-oxibelt-cache-reason"] == "background_refresh") or (.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored")'
  sleep 2
  second_stale="$(client_request "example.test" "/app/bg?sequence_key=bg-refresh&body_sequence=old%7Cold%7Cnew&cache_control=public-stale-revalidate&content_type=text/plain" 200)"
  assert_response_jq "${second_stale}" '.body == "old" or .body == "new"'
  sleep 1
  refreshed="$(client_request "example.test" "/app/bg?sequence_key=bg-refresh&body_sequence=old%7Cold%7Cnew&cache_control=public-stale-revalidate&content_type=text/plain" 200)"
  assert_response_jq "${refreshed}" '.body == "new"'
}
