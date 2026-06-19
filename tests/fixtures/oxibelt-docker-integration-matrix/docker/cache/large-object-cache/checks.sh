
run_case_checks() {
  local path first cached
  path="/app/large?body_repeat=131072&body_repeat_char=L&cache_control=public&content_type=text/plain"
  first="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${first}" '(.body | length) == 131072'

  docker rm -f "${http_container}" >/dev/null
  cached="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${cached}" '(.body | length) == 131072'
}
