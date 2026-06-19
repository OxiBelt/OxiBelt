
run_case_checks() {
  local default_response retry_response
  default_response="$(client_request_with_headers "default.example.test" "/write" 503 "POST" "payload")"
  assert_body_jq "${default_response}" '.upstream == "http-upstream" and .method == "POST"'

  retry_response="$(client_request_with_headers "retry.example.test" "/write" 200 "POST" "payload")"
  assert_body_jq "${retry_response}" '.upstream == "alt-upstream" and .method == "POST"'
}
