
run_case_checks() {
  local response
  response="$(client_request "example.test" "/assets/app.css?body=body-css&cache_control=public&content_type=text/css" 200)"
  assert_response_jq "${response}" '.body == "body-css"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'
  docker rm -f "${http_container}" >/dev/null
  response="$(client_request "example.test" "/assets/app.css?body=body-css&cache_control=public&content_type=text/css" 200)"
  assert_response_jq "${response}" '.body == "body-css"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "hit" and .headers["x-oxibelt-cache-reason"] == "fresh"'
}
