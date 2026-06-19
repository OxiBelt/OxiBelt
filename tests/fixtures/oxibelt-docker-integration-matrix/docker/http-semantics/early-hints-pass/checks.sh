
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/early?early_hints=1&early_link=</app.css>; rel=preload; as=style" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/early?early_hints=1&early_link=%3C/app.css%3E;%20rel=preload;%20as=style"'
}
