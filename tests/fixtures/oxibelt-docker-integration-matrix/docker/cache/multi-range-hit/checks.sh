
run_case_checks() {
  local path response excessive_range
  path="/app/multi-range?body=0123456789&cache_control=public&content_type=text/plain"
  response="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${response}" '.body == "0123456789"'
  docker rm -f "${http_container}" >/dev/null
  response="$(client_request_with_headers "example.test" "${path}" 206 "GET" "" "Range: bytes=0-1,8-9")"
  assert_response_jq "${response}" '.headers["content-type"] | startswith("multipart/byteranges; boundary=")'
  assert_response_jq "${response}" '.body | contains("Content-Range: bytes 0-1/10") and contains("Content-Range: bytes 8-9/10")'
  excessive_range="bytes=0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0,0-0"
  response="$(client_request_with_headers "example.test" "${path}" 200 "GET" "" "Range: ${excessive_range}")"
  assert_response_jq "${response}" '.body == "0123456789"'
  assert_response_jq "${response}" '(.headers["content-type"] // "") == "text/plain"'
}
