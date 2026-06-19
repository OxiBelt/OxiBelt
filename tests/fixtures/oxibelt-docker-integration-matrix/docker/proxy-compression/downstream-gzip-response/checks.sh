
run_case_checks() {
  local response decoded identity br_response
  response="$(client_request_with_headers "example.test" "/app/compressible?case=gzip" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${response}" '.headers["content-encoding"] == "gzip"
    and .headers["content-length"] == null
    and (.headers.vary | ascii_downcase | contains("accept-encoding"))'
  decoded="$(
    jq -r '.body_base64' <<<"${response}" |
      python3 -c 'import base64,gzip,sys; sys.stdout.write(gzip.decompress(base64.b64decode(sys.stdin.read())).decode("utf-8"))'
  )"
  if ! jq -e '.upstream == "http-upstream"
      and .path == "/origin/app/compressible?case=gzip"
      and .headers["accept-encoding"] == null' <<<"${decoded}" >/dev/null; then
    echo "Decoded gzip body assertion failed" >&2
    echo "${decoded}" >&2
    fail_with_diagnostics "decoded gzip response body did not match"
  fi

  identity="$(client_request_with_headers "example.test" "/app/identity?case=identity" 200 "GET" "" "Accept-Encoding: identity")"
  assert_response_jq "${identity}" '.headers["content-encoding"] == null'
  assert_body_jq "${identity}" '.upstream == "http-upstream"
    and .path == "/origin/app/identity?case=identity"
    and .headers["accept-encoding"] == null'

  br_response="$(client_request_with_headers "example.test" "/app/br?case=preference" 200 "GET" "" "Accept-Encoding: gzip, br")"
  assert_response_jq "${br_response}" '.headers["content-encoding"] == "br"
    and .headers["content-length"] == null'
}
