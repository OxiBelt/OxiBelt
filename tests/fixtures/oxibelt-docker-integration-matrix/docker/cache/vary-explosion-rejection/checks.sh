
run_case_checks() {
  local path first rejected cached miss
  path="/app/vary-cap?sequence_key=vary-cap&body_sequence=vary-a%7Cvary-b%7Cvary-c&vary=X-Variant&cache_control=public&content_type=text/plain"
  first="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Variant: a")"
  rejected="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Variant: b")"
  assert_response_jq "${first}" '.body == "vary-a"'
  assert_response_jq "${rejected}" '.body == "vary-b"'

  docker rm -f "${http_container}" >/dev/null
  cached="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "X-Variant: a")"
  miss="$(client_request_with_headers "example.test" "${path}" 502 "GET" "" "X-Variant: b")"
  assert_response_jq "${cached}" '.body == "vary-a"'
  assert_response_jq "${miss}" '.status == 502'
}
