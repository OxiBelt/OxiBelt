run_case_checks() {
  local seed alias revalidated changed_policy owner_refresh owner_replaced purge after_purge
  local seed_path="/app/nvs-lifecycle?noise=one&keep=stable&body=owner&content_type=text/plain&cache_control=public&etag=nvs-owner-v1&no_vary_search=params%3D%28%22noise%22%29"
  local alias_path="${seed_path/noise=one/noise=two}"

  seed="$(client_request "example.test" "${seed_path}" 200)"
  assert_response_jq "${seed}" '.headers["x-oxibelt-cache"] == "miss" and .headers["no-vary-search"] == "params=(\"noise\")"'

  alias="$(client_request "example.test" "${alias_path}" 200)"
  assert_response_jq "${alias}" '.headers["x-oxibelt-cache"] == "hit" and .body == "owner"'

  revalidated="$(client_request_with_headers "example.test" "${alias_path}" 200 "GET" "" "Cache-Control: no-cache")"
  assert_response_jq "${revalidated}" '.headers["x-oxibelt-cache"] == "revalidated" and .headers["x-oxibelt-cache-reason"] == "not_modified" and .headers["no-vary-search"] == "params=(\"noise\")"'

  # A changed 304 policy which no longer covers this alias must trigger an
  # unconditional request for the original alias URI. The 304 itself must
  # never escape to the downstream client.
  local changed_seed="/app/nvs-304-change?noise=one&keep=stable&body_sequence=owner%7Calias-fallback&sequence_key=nvs-304-change&content_type=text/plain&cache_control=public&etag=nvs-owner-v2&no_vary_search_sequence=params%3D%28%22noise%22%29%7Cparams%3D%28%22other%22%29"
  local changed_alias="${changed_seed/noise=one/noise=two}"
  seed="$(client_request "example.test" "${changed_seed}" 200)"
  assert_response_jq "${seed}" '.headers["x-oxibelt-cache"] == "miss" and .body == "owner" and .headers["no-vary-search"] == "params=(\"noise\")"'
  changed_policy="$(client_request_with_headers "example.test" "${changed_alias}" 200 "GET" "" "Cache-Control: no-cache")"
  assert_response_jq "${changed_policy}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored" and .headers["x-sequence-index"] == "2" and .body == "alias-fallback" and .headers["no-vary-search"] == "params=(\"other\")"'

  # An owner 200 which drops NVS cannot refresh an alias from the owner
  # payload. It must fetch the original alias, which the sequence marks as 2.
  local missing_owner="/app/nvs-200-missing?noise=one&body_sequence=owner-bytes%7Cowner-new%7Calias-new&sequence_key=nvs-200-missing&content_type=text/plain&cache_control=public&etag_sequence=nvs-missing-v1%7Cnvs-missing-v2&no_vary_search_sequence=params%3D%28%22noise%22%29%7C%7C"
  local missing_alias="${missing_owner/noise=one/noise=two}"
  seed="$(client_request "example.test" "${missing_owner}" 200)"
  assert_response_jq "${seed}" '.headers["x-oxibelt-cache"] == "miss" and .body == "owner-bytes"'
  owner_refresh="$(client_request_with_headers "example.test" "${missing_alias}" 200 "GET" "" "Cache-Control: no-cache")"
  assert_response_jq "${owner_refresh}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored" and .headers["x-sequence-index"] == "2" and .body == "alias-new" and .headers["no-vary-search"] == null'

  # Narrowing the owner policy has the same requirement: index 1 is the
  # owner-only response and index 2 proves the original alias was fetched.
  local narrowed_owner="/app/nvs-200-narrow?noise=one&body_sequence=owner-bytes%7Cowner-new%7Calias-new&sequence_key=nvs-200-narrow&content_type=text/plain&cache_control=public&etag_sequence=nvs-narrow-v1%7Cnvs-narrow-v2&no_vary_search_sequence=params%3D%28%22noise%22%29%7Cparams%3D%28%22other%22%29"
  local narrowed_alias="${narrowed_owner/noise=one/noise=two}"
  seed="$(client_request "example.test" "${narrowed_owner}" 200)"
  assert_response_jq "${seed}" '.headers["x-oxibelt-cache"] == "miss" and .body == "owner-bytes"'
  owner_refresh="$(client_request_with_headers "example.test" "${narrowed_alias}" 200 "GET" "" "Cache-Control: no-cache")"
  assert_response_jq "${owner_refresh}" '.headers["x-oxibelt-cache"] == "miss" and .headers["x-oxibelt-cache-reason"] == "stored" and .headers["x-sequence-index"] == "2" and .body == "alias-new" and .headers["no-vary-search"] == "params=(\"other\")"'

  # If the refreshed owner still accepts the alias, the new representation
  # replaces the owner exact key. A subsequent owner request must hit that
  # entry rather than issuing a third origin request or creating an alias key.
  local accepted_owner="/app/nvs-200-owner?noise=one&body_sequence=owner-old%7Cowner-new&sequence_key=nvs-200-owner&content_type=text/plain&cache_control=public&etag_sequence=nvs-owner-v1%7Cnvs-owner-v2&no_vary_search_sequence=params%3D%28%22noise%22%29"
  local accepted_alias="${accepted_owner/noise=one/noise=two}"
  seed="$(client_request "example.test" "${accepted_owner}" 200)"
  assert_response_jq "${seed}" '.headers["x-oxibelt-cache"] == "miss" and .body == "owner-old"'
  owner_refresh="$(client_request_with_headers "example.test" "${accepted_alias}" 200 "GET" "" "Cache-Control: no-cache")"
  assert_response_jq "${owner_refresh}" '.body == "owner-new" and .headers["x-sequence-index"] == "1"'
  owner_replaced="$(client_request "example.test" "${accepted_owner}" 200)"
  assert_response_jq "${owner_replaced}" '.headers["x-oxibelt-cache"] == "hit" and .body == "owner-new" and .headers["x-sequence-index"] == "1"'

  # Unsafe requests invalidate equivalent owners across raw query spellings.
  local unsafe_seed="${seed_path/nvs-lifecycle/nvs-unsafe}"
  local unsafe_alias="${unsafe_seed/noise=one/noise=two}"
  seed="$(client_request "example.test" "${unsafe_seed}" 200)"
  assert_response_jq "${seed}" '.headers["x-oxibelt-cache"] == "miss"'
  alias="$(client_request "example.test" "${unsafe_alias}" 200)"
  assert_response_jq "${alias}" '.headers["x-oxibelt-cache"] == "hit"'
  client_request_with_headers "example.test" "${unsafe_seed/noise=one/noise=mutation}" 200 POST "mutation" >/dev/null
  alias="$(client_request "example.test" "${unsafe_alias}" 200)"
  assert_response_jq "${alias}" '.headers["x-oxibelt-cache"] == "miss"'

  purge="$(client_request_with_headers_on_port 9092 "proxy" "/cache/purge?policy=default&scheme=https&host=example.test&uri=/app/nvs-lifecycle%3Fnoise%3Done%26keep%3Dstable%26body%3Downer%26content_type%3Dtext%2Fplain%26cache_control%3Dpublic%26etag%3Dnvs-owner-v1%26no_vary_search%3Dparams%253D%2528%2522noise%2522%2529" 200 "POST" "" "Authorization: Bearer matrix-admin-token")"
  assert_response_jq "${purge}" '.body | test("^purged=[1-9][0-9]*\\n$")'

  docker rm -f "${http_container}" >/dev/null
  after_purge="$(client_request "example.test" "${alias_path}" 502)"
  assert_response_jq "${after_purge}" '.status == 502'
}
