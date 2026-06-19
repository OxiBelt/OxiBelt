
run_case_checks() {
  local path first cached
  path="/app/huge-disk?body_repeat=131072&body_repeat_char=H&cache_control=public&content_type=text/plain"
  first="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${first}" '(.body | length) == 131072'
  assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'
  sleep 1
  docker rm -f "${http_container}" >/dev/null
  cached="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${cached}" '(.body | length) == 131072'
  assert_response_jq "${cached}" '.headers["x-oxibelt-cache"] == "hit" and .headers["x-oxibelt-cache-reason"] == "fresh"'
}
