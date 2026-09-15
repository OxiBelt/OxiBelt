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

run_case_checks() {
  local downstream target path first second changed expected_upstream
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
    done
  done
}
