
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/range?body=0123456789&cache_control=public&content_type=text/plain" 200)"
  assert_response_jq "${response}" '.body == "0123456789"'
  docker rm -f "${http_container}" >/dev/null
  response="$(client_request_with_headers "example.test" "/app/range?body=0123456789&cache_control=public&content_type=text/plain" 206 "GET" "" "Range: bytes=2-5")"
  assert_response_jq "${response}" '.body == "2345" and .headers["content-range"] == "bytes 2-5/10"'
}
