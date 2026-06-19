
run_case_checks() {
  local compressed uncompressed
  compressed="$(client_request_with_headers "example.test" "/on/compress?body_repeat=2048&body_repeat_char=x&content_type=text/plain" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${compressed}" '.headers["content-encoding"] == "gzip"'

  uncompressed="$(client_request_with_headers "example.test" "/off/compress?body_repeat=2048&body_repeat_char=x&content_type=text/plain" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${uncompressed}" '.headers["content-encoding"] == null'
  assert_response_jq "${uncompressed}" '.body | length == 2048'
}
