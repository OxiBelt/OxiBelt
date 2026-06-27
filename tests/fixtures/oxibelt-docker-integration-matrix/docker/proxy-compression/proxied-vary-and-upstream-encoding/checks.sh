
run_case_checks() {
  local denied allowed decoded

  denied="$(client_request_with_headers "example.test" "/app/proxied-denied?case=via" 200 "GET" "" "Accept-Encoding: gzip" "Via: 1.1 intermediate")"
  assert_response_jq "${denied}" '.headers["content-encoding"] == null
    and .headers.vary == null'
  assert_body_jq "${denied}" '.headers["accept-encoding"] == "gzip"
    and .headers.via == "1.1 intermediate"'

  allowed="$(client_request_with_headers "example.test" "/app/proxied-allowed?case=via&cache_control_value=no-cache" 200 "GET" "" "Accept-Encoding: gzip" "Via: 1.1 intermediate")"
  assert_response_jq "${allowed}" '.headers["content-encoding"] == "gzip"
    and .headers.vary == null
    and .headers["content-length"] == null'
  decoded="$(
    jq -r '.body_base64' <<<"${allowed}" |
      python3 -c 'import base64,gzip,sys; sys.stdout.write(gzip.decompress(base64.b64decode(sys.stdin.read())).decode("utf-8"))'
  )"
  if ! jq -e '.headers["accept-encoding"] == "gzip"
      and .headers.via == "1.1 intermediate"
      and .path == "/origin/app/proxied-allowed?case=via&cache_control_value=no-cache"' <<<"${decoded}" >/dev/null; then
    echo "Decoded proxied gzip body assertion failed" >&2
    echo "${decoded}" >&2
    fail_with_diagnostics "proxied compression response body did not match"
  fi
}
