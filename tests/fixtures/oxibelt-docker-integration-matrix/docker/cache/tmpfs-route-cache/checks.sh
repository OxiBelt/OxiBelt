
run_case_checks() {
  local response nvs_seed nvs_alias
  response="$(client_request "example.test" "/app/cache?item=1" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored"'

  nvs_seed="$(client_request "example.test" "/app/nvs-cache?noise=one&body=nvs-tmpfs&cache_control=public&content_type=text/plain&no_vary_search=params%3D%28%22noise%22%29" 200)"
  assert_response_jq "${nvs_seed}" '.headers["x-oxibelt-cache"] == "miss" and .body == "nvs-tmpfs"'

  docker rm -f "${http_container}" >/dev/null

  response="$(client_request "example.test" "/app/cache?item=1" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/cache?item=1"'
  assert_response_jq "${response}" '.headers["x-oxibelt-cache"] == "hit" and .headers["x-oxibelt-cache-reason"] == "fresh"'

  nvs_alias="$(client_request "example.test" "/app/nvs-cache?noise=two&body=nvs-tmpfs&cache_control=public&content_type=text/plain&no_vary_search=params%3D%28%22noise%22%29" 200)"
  assert_response_jq "${nvs_alias}" '.headers["x-oxibelt-cache"] == "hit" and .body == "nvs-tmpfs" and .headers["no-vary-search"] == "params=(\"noise\")"'
}
