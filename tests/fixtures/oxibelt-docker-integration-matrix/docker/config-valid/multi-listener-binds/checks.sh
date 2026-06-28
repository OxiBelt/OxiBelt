
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/primary-https" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/primary-https"'

  response="$(client_request_on_port 9443 "example.test" "/app/secondary-https" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/secondary-https"'

  response="$(plain_client_request "example.test" "/app/primary-http" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/primary-http"'

  response="$(plain_client_request_on_port 8081 "example.test" "/app/secondary-http" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/secondary-http"'
}
