
run_case_checks() {
  local path first miss
  path="/app/large-over-memory?body_repeat=131072&body_repeat_char=M&cache_control=public&content_type=text/plain"
  first="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${first}" '(.body | length) == 131072'

  docker rm -f "${http_container}" >/dev/null
  miss="$(client_request "example.test" "${path}" 502)"
  assert_response_jq "${miss}" '.status == 502'
}
