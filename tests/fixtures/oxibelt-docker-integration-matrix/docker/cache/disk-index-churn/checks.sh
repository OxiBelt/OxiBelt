
run_case_checks() {
  local first second third fourth newest evicted
  first="$(client_request "example.test" "/app/churn-a?body_repeat=128&body_repeat_char=A&cache_control=public&content_type=text/plain" 200)"
  second="$(client_request "example.test" "/app/churn-b?body_repeat=128&body_repeat_char=B&cache_control=public&content_type=text/plain" 200)"
  third="$(client_request "example.test" "/app/churn-c?body_repeat=128&body_repeat_char=C&cache_control=public&content_type=text/plain" 200)"
  fourth="$(client_request "example.test" "/app/churn-d?body_repeat=128&body_repeat_char=D&cache_control=public&content_type=text/plain" 200)"
  assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${second}" '.headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${third}" '.headers["x-oxibelt-cache"] == "miss"'
  assert_response_jq "${fourth}" '.headers["x-oxibelt-cache"] == "miss"'
  sleep 1
  docker rm -f "${http_container}" >/dev/null
  newest="$(client_request "example.test" "/app/churn-d?body_repeat=128&body_repeat_char=D&cache_control=public&content_type=text/plain" 200)"
  assert_response_jq "${newest}" '(.body | length) == 128 and .headers["x-oxibelt-cache"] == "hit"'
  evicted="$(client_request_to_target "proxy" "example.test" "/app/churn-a?body_repeat=128&body_repeat_char=A&cache_control=public&content_type=text/plain" 502,504)"
  assert_response_jq "${evicted}" '.status == 502 or .status == 504'
}
