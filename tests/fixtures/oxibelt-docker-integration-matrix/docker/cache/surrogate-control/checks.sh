
run_case_checks() {
  local path first cached
  path="/app/surrogate?sequence_key=surrogate-control&body_sequence=surrogate-a%7Csurrogate-b&cache_control=no-store&surrogate_control=max-age%3D60&content_type=text/plain"
  first="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${first}" '.body == "surrogate-a" and (.headers["surrogate-control"] == null)'

  docker rm -f "${http_container}" >/dev/null
  cached="$(client_request "example.test" "${path}" 200)"
  assert_response_jq "${cached}" '.body == "surrogate-a" and (.headers["surrogate-control"] == null)'
}
