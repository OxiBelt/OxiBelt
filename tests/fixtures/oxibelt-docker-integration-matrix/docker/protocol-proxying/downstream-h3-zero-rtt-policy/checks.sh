
run_case_checks() {
  local get_response post_response
  get_response="$(protocol_probe_client_with_headers "h3" "example.test" "/app/early-get" 200 "GET" "" "Early-Data: 1")"
  assert_body_jq "${get_response}" '.path == "/origin/app/early-get"'
  post_response="$(protocol_probe_client_with_headers "h3" "example.test" "/app/early-post" 200 "POST" "unsafe" "Early-Data: 1")"
  assert_body_jq "${post_response}" '.path == "/origin/app/early-post" and .method == "POST"'
}
