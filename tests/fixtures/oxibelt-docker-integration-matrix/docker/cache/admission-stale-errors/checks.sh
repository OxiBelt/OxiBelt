
run_case_checks() {
  local first second third stale rejected
  first="$(client_request "example.test" "/app/admit?sequence_key=admit&body_sequence=admitted%7Cadmitted%7Cshould-not-serve&status_sequence=200%7C200%7C500&cache_control=public-stale-error&content_type=text/plain" 200)"
  second="$(client_request "example.test" "/app/admit?sequence_key=admit&body_sequence=admitted%7Cadmitted%7Cshould-not-serve&status_sequence=200%7C200%7C500&cache_control=public-stale-error&content_type=text/plain" 200)"
  assert_response_jq "${first}" '.body == "admitted"'
  assert_response_jq "${second}" '.body == "admitted"'
  assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "admission_warming"'
  assert_response_jq "${second}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'
  sleep 2
  stale="$(client_request "example.test" "/app/admit?sequence_key=admit&body_sequence=admitted%7Cadmitted%7Cshould-not-serve&status_sequence=200%7C200%7C500&cache_control=public-stale-error&content_type=text/plain" 200)"
  assert_response_jq "${stale}" '.body == "admitted"'
  assert_response_jq "${stale}" '.headers["x-oxibelt-cache"] == "stale" and .headers["x-oxibelt-cache-reason"] == "stale_if_error"'

  rejected="$(client_request "example.test" "/app/reject-content-type?body=json&cache_control=public&content_type=application/json" 200)"
  assert_response_jq "${rejected}" '.body == "json"'
  docker rm -f "${http_container}" >/dev/null
  third="$(client_request "example.test" "/app/reject-content-type?body=json&cache_control=public&content_type=application/json" 502)"
  assert_response_jq "${third}" '.status == 502'
}
