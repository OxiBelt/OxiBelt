
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/reload" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/reload"'

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy

  response="$(client_request "example.test" "/app/reload" 403)"
  assert_response_jq "${response}" '.body == "hot reloaded oxirule"'
}
