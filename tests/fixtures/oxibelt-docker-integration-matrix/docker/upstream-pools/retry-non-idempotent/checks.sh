
run_case_checks() {
  local default_response retry_response resumable_response
  default_response="$(client_request_with_headers "default.example.test" "/write" 503 "POST" "payload")"
  assert_body_jq "${default_response}" '.upstream == "http-upstream" and .method == "POST"'

  retry_response="$(client_request_with_headers \
    "retry.example.test" "/write" 200 "POST" "payload" \
    "Upload-Draft-Interop-Version: 9" \
    "Upload-Offset: invalid")"
  assert_body_jq "${retry_response}" '.upstream == "alt-upstream" and .method == "POST"'

  resumable_response="$(client_request_with_headers \
    "resumable.example.test" "/write" 503 "POST" "payload" \
    "Upload-Draft-Interop-Version: 9" \
    "Upload-Complete: ?0")"
  assert_body_jq "${resumable_response}" '.upstream == "http-upstream" and .method == "POST"'
}
