
run_case_checks() {
  local response
  response="$(plain_client_request "example.test" "/app/plain" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"
    and .path == "/origin/app/plain"
    and .headers["x-forwarded-proto"] == "http"'
}
