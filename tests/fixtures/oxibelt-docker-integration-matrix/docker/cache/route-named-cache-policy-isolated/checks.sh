
run_case_checks() {
  local named_seed named_hit default_seed default_hit
  named_seed="$(client_request "example.test" "/named/object?body=named-a&cache_control=public&content_type=text/plain" 200)"
  assert_response_jq "${named_seed}" '.body == "named-a"'
  assert_response_jq "${named_seed}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'

  named_hit="$(client_request "example.test" "/named/object?body=named-a&cache_control=public&content_type=text/plain" 200)"
  assert_response_jq "${named_hit}" '.body == "named-a"'
  assert_response_jq "${named_hit}" '.headers["x-oxibelt-cache"] == "hit" and .headers["x-oxibelt-cache-reason"] == "fresh"'

  default_seed="$(client_request "example.test" "/default/object?body=default-a&cache_control=public&content_type=text/plain" 200)"
  assert_response_jq "${default_seed}" '.body == "default-a"'
  assert_response_jq "${default_seed}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'

  default_hit="$(client_request "example.test" "/default/object?body=default-a&cache_control=public&content_type=text/plain" 200)"
  assert_response_jq "${default_hit}" '.body == "default-a"'
  assert_response_jq "${default_hit}" '.headers["x-oxibelt-cache"] == "hit" and .headers["x-oxibelt-cache-reason"] == "fresh"'
}
