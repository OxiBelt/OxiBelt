
run_case_checks() {
  local first second third
  first="$(client_request_with_headers "example.test" "/app/vary?vary=X-Variant&cache_control=public" 200 "GET" "" "X-Variant: a")"
  second="$(client_request_with_headers "example.test" "/app/vary?vary=X-Variant&cache_control=public" 200 "GET" "" "X-Variant: b")"
  third="$(client_request_with_headers "example.test" "/app/vary?vary=X-Variant&cache_control=public" 200 "GET" "" "X-Variant: a")"
  assert_body_jq "${first}" '.headers["x-variant"] == "a"'
  assert_body_jq "${second}" '.headers["x-variant"] == "b"'
  assert_body_jq "${third}" '.headers["x-variant"] == "a"'
}
