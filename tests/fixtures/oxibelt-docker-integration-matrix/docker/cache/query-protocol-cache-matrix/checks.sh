# QUERY has request content, so each downstream/upstream combination proves
# both the transported body and the cache identity. A repeated body is a hit;
# a changed body at the same target is a distinct miss.
query_request() {
  local downstream="$1"
  local path="$2"
  local body="$3"
  if [[ "${downstream}" == "h1" ]]; then
    client_request_with_headers \
      "example.test" "${path}" 200 QUERY "${body}" 'Content-Type: application/json'
  else
    protocol_probe_client_with_headers \
      "${downstream}" "example.test" "${path}" 200 QUERY "${body}" 'Content-Type: application/json'
  fi
}

ordinary_get_request() {
  local downstream="$1"
  local path="$2"
  shift 2
  if [[ "${downstream}" == "h1" ]]; then
    client_request_with_headers "example.test" "${path}" 200 GET "" "$@"
  else
    protocol_probe_client_with_headers \
      "${downstream}" "example.test" "${path}" 200 GET "" "$@"
  fi
}

run_case_checks() {
  local downstream target path first second changed cacheable_get cached_get cached_header_get expected_upstream
  for downstream in h1 h2 h3; do
    for target in h1 h2 h3; do
      expected_upstream="${target}-upstream"
      if [[ "${target}" == "h1" ]]; then expected_upstream="http-upstream"; fi
      path="/${target}/query-${downstream}"
      first="$(query_request "${downstream}" "${path}" '{"selector":"one"}')"
      assert_body_jq "${first}" ".upstream == \"${expected_upstream}\" and .method == \"QUERY\" and .body == \"{\\\"selector\\\":\\\"one\\\"}\""
      assert_response_jq "${first}" '.headers["x-oxibelt-cache"] == "miss"'

      second="$(query_request "${downstream}" "${path}" '{"selector":"one"}')"
      assert_body_jq "${second}" ".upstream == \"${expected_upstream}\" and .method == \"QUERY\" and .body == \"{\\\"selector\\\":\\\"one\\\"}\""
      assert_response_jq "${second}" '.headers["x-oxibelt-cache"] == "hit"'

      changed="$(query_request "${downstream}" "${path}" '{"selector":"two"}')"
      assert_body_jq "${changed}" ".upstream == \"${expected_upstream}\" and .method == \"QUERY\" and .body == \"{\\\"selector\\\":\\\"two\\\"}\""
      assert_response_jq "${changed}" '.headers["x-oxibelt-cache"] == "miss"'

      # Upload-looking fields on an ordinary GET are neither a resumable
      # creation nor append. They must not suppress cache fills or hits.
      path="/${target}/ordinary-get-${downstream}"
      cacheable_get="$(ordinary_get_request \
        "${downstream}" "${path}" \
        "Upload-Draft-Interop-Version: 9" \
        "Upload-Offset: invalid")"
      assert_body_jq "${cacheable_get}" ".upstream == \"${expected_upstream}\" and .method == \"GET\""
      assert_response_jq "${cacheable_get}" '.headers["x-oxibelt-cache"] == "miss"'

      cached_get="$(ordinary_get_request "${downstream}" "${path}")"
      assert_body_jq "${cached_get}" ".upstream == \"${expected_upstream}\" and .method == \"GET\""
      assert_response_jq "${cached_get}" '.headers["x-oxibelt-cache"] == "hit"'

      cached_header_get="$(ordinary_get_request \
        "${downstream}" "${path}" \
        "Upload-Draft-Interop-Version: 9" \
        "Upload-Offset: invalid")"
      assert_body_jq "${cached_header_get}" ".upstream == \"${expected_upstream}\" and .method == \"GET\""
      assert_response_jq "${cached_header_get}" '.headers["x-oxibelt-cache"] == "hit"'
    done
  done
}
