
run_case_checks() {
  local path response revalidated conditional past_path past_first past_second
  path="/app/rfc-smaxage?body=smaxage&cache_control_value=public%2C%20max-age%3D0%2C%20s-maxage%3D60&content_type=text/plain"
  response="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${response}" '.body == "smaxage"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'
  response="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "hit" and .headers["x-oxibelt-cache-reason"] == "fresh"'

  path="/app/rfc-revalidate?body=reval&cache_control=public&etag=rfc-v1&content_type=text/plain"
  response="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'
  revalidated="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "Pragma: no-cache")"
  assert_response_jq "${revalidated}" '.body == "reval"'
  assert_response_jq "${revalidated}" '.headers["x-oxibelt-cache"] == "revalidated" and .headers["x-oxibelt-cache-reason"] == "not_modified"'
  conditional="$(client_request_with_headers "example.test" "${path}" 304 "GET" "" "If-None-Match: rfc-v1")"
  assert_response_jq "${conditional}" '.headers["x-oxibelt-cache"] == "hit" and .headers["x-oxibelt-cache-reason"] == "fresh" and (.headers["age"] != null)'

  past_path="/app/rfc-past?sequence_key=rfc-past&body_sequence=past-first%7Cpast-second&expires=Tue%2C%2001%20Jan%201980%2000%3A00%3A00%20GMT&content_type=text/plain"
  past_first="$(client_request "example.test" "${past_path}" 200)"
  assert_response_jq "${past_first}" '.body == "past-first"'
  assert_response_jq "${past_first}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "not_cacheable"'
  past_second="$(client_request "example.test" "${past_path}" 200)"
  assert_response_jq "${past_second}" '.body == "past-second"'
  assert_response_jq "${past_second}" '.headers["x-oxibelt-cache"] == "miss"'
}
