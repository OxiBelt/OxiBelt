run_case_checks() {
  local protocol response
  for protocol in h1 h2 h3; do
    local args=(
      --header "Want-Content-Digest: sha-256=1"
      --header "Want-Repr-Digest: sha-256=1"
      --header "Want-Unencoded-Digest: sha-256=1"
    )
    if [[ "${protocol}" == "h1" ]]; then
      args+=(--header "TE: trailers")
    fi
    response="$(protocol_probe_client "${protocol}" example.test "/stream?chunked_response=1&body=drop-trailers" 200 "${args[@]}")"
    assert_response_jq "${response}" '.status == 200 and .body == "drop-trailers"
      and .headers["content-digest"] == null and .headers["repr-digest"] == null and .headers["unencoded-digest"] == null
      and .trailers["content-digest"] == null and .trailers["repr-digest"] == null and .trailers["unencoded-digest"] == null'
    if [[ "${protocol}" == "h1" ]]; then
      assert_response_jq "${response}" '.wire.chunked == true and .wire.chunk_count >= 1'
    fi
  done
}
