
run_case_checks() {
  local blocked_body bomb_body response safe_response
  blocked_body="$(gzip_text_base64 "prefix compressed-secret suffix")"
  response="$(client_request_with_headers_body_base64 "example.test" "/app/compressed-request" 403 "POST" "${blocked_body}" "Content-Encoding: gzip" "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "compressed request blocked"'

  bomb_body="$(gzip_repeat_base64 2048)"
  response="$(client_request_with_headers_body_base64 "example.test" "/app/bomb" 413 "POST" "${bomb_body}" "Content-Encoding: gzip" "Content-Type: text/plain")"
  assert_response_jq "${response}" '.body == "request body is too large"'

  response="$(client_request "example.test" "/app/compressed-response?content_encoding=gzip&content_type=text/plain&body=prefix-response-secret-suffix" 502)"
  assert_response_jq "${response}" '.body == "compressed response blocked"'

  safe_response="$(client_request_with_headers "example.test" "/app/compressed-safe?content_encoding=gzip&content_type=text/plain&body=safe-response-safe-response" 200 "GET" "" "Accept-Encoding: gzip")"
  assert_response_jq "${safe_response}" '.headers["content-encoding"] == "gzip"'
}

gzip_text_base64() {
  python3 - "$1" <<'PY'
import base64
import gzip
import sys

print(base64.b64encode(gzip.compress(sys.argv[1].encode("utf-8"))).decode("ascii"))
PY
}

gzip_repeat_base64() {
  python3 - "$1" <<'PY'
import base64
import gzip
import sys

print(base64.b64encode(gzip.compress(("x" * int(sys.argv[1])).encode("ascii"))).decode("ascii"))
PY
}
