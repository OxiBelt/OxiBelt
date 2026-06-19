
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/cache?item=1" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'

  docker rm -f "${http_container}" >/dev/null

  response="$(client_request "example.test" "/app/cache?item=1" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/cache?item=1"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "hit" and .headers["x-oxibelt-cache-reason"] == "fresh"'
}
