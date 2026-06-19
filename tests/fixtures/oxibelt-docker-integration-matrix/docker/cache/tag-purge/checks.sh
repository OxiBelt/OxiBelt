
run_case_checks() {
  local first second purge first_after second_after
  first="$(client_request "example.test" "/app/tag-a?sequence_key=tag-a&body_sequence=tag-a%7Ctag-a-after&cache_control=public&content_type=text/plain&surrogate_key=release-1%20assets" 200)"
  second="$(client_request "example.test" "/app/tag-b?sequence_key=tag-b&body_sequence=tag-b%7Ctag-b-after&cache_control=public&content_type=text/plain&surrogate_key=release-2%20assets" 200)"
  assert_response_jq "${first}" '.body == "tag-a"'
  assert_response_jq "${second}" '.body == "tag-b"'

  purge="$(plain_client_request_with_headers_on_port 9092 "proxy" "/cache/purge-tag?policy=default&tag=release-1" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${purge}" '.body == "purged=1\n"'

  first_after="$(client_request "example.test" "/app/tag-a?sequence_key=tag-a&body_sequence=tag-a%7Ctag-a-after&cache_control=public&content_type=text/plain&surrogate_key=release-1%20assets" 200)"
  second_after="$(client_request "example.test" "/app/tag-b?sequence_key=tag-b&body_sequence=tag-b%7Ctag-b-after&cache_control=public&content_type=text/plain&surrogate_key=release-2%20assets" 200)"
  assert_response_jq "${first_after}" '.body == "tag-a-after"'
  assert_response_jq "${second_after}" '.body == "tag-b"'
}
