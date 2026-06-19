
run_case_checks() {
  local response
  response="$(client_request_with_headers "tie.example.test" "/same/path?tie=yes" 200 "GET" "" "X-Tie: yes")"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/same/path?tie=yes"'
}
