
assert_same_static_response() {
  local left="$1"
  local right="$2"
  local filter="$3"
  local left_value right_value
  left_value="$(jq -c "${filter}" <<<"${left}")"
  right_value="$(jq -c "${filter}" <<<"${right}")"
  if [[ "${left_value}" != "${right_value}" ]]; then
    echo "plain static: ${left_value}" >&2
    echo "https static: ${right_value}" >&2
    fail_with_diagnostics "static sendfile/general responses diverged"
  fi
}

run_case_checks() {
  local plain https etag logged logs matching

  plain="$(plain_client_request "static-equivalence.example.test" "/static/ok.txt" 200)"
  https="$(client_request "static-equivalence.example.test" "/static/ok.txt" 200)"
  assert_same_static_response "${plain}" "${https}" '{status, body_base64, headers: {
    "content-length": .headers["content-length"],
    "content-type": .headers["content-type"],
    "accept-ranges": .headers["accept-ranges"]
  }}'
  assert_response_jq "${plain}" '.body == "static ok\n"'

  logged="$(plain_client_request_with_headers_on_port 8080 "static-equivalence.example.test" "/static/ok.txt?case=system-log" 200 "GET" "" "User-Agent: first-agent" "User-Agent: second-agent")"
  assert_response_jq "${logged}" '.body == "static ok\n"'
  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  matching="$(grep -F '"scope":"system"' <<<"${logs}" | grep -F '"path":"/static/ok.txt"' | grep -F '"status":200' | grep -F '"route":"static-equivalence"' || true)"
  if [[ -z "${matching}" ]]; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected static sendfile system access log JSON on stdout"
  fi
  if ! grep -F '"user_agent":{"values":["first-agent","second-agent"],"is_truncated":false}' <<<"${matching}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "expected static sendfile system access log to preserve duplicate User-Agent values"
  fi

  plain="$(plain_client_request_with_headers_on_port 8080 "static-equivalence.example.test" "/static/ok.txt" 200 "HEAD" "")"
  https="$(client_request_with_headers "static-equivalence.example.test" "/static/ok.txt" 200 "HEAD" "")"
  assert_same_static_response "${plain}" "${https}" '{status, body_base64, headers: {
    "content-length": .headers["content-length"],
    "content-type": .headers["content-type"]
  }}'
  assert_response_jq "${plain}" '.body == ""'

  plain="$(plain_client_request_with_headers_on_port 8080 "static-equivalence.example.test" "/static/range.txt" 206 "GET" "" "Range: bytes=0-5")"
  https="$(client_request_with_headers "static-equivalence.example.test" "/static/range.txt" 206 "GET" "" "Range: bytes=0-5")"
  assert_same_static_response "${plain}" "${https}" '{status, body_base64, headers: {
    "content-length": .headers["content-length"],
    "content-range": .headers["content-range"],
    "accept-ranges": .headers["accept-ranges"]
  }}'
  assert_response_jq "${plain}" '.body == "012345"'

  etag="$(jq -r '.headers.etag' <<<"${https}")"
  plain="$(plain_client_request_with_headers_on_port 8080 "static-equivalence.example.test" "/static/range.txt" 304 "GET" "" "If-None-Match: ${etag}")"
  https="$(client_request_with_headers "static-equivalence.example.test" "/static/range.txt" 304 "GET" "" "If-None-Match: ${etag}")"
  assert_same_static_response "${plain}" "${https}" '{status, body_base64, headers: {
    etag: .headers.etag,
    "accept-ranges": .headers["accept-ranges"]
  }}'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu '
    rm -f /etc/oxibelt/config/public/link.txt
    ln -s /etc/oxibelt/config/outside-secret.txt /etc/oxibelt/config/public/link.txt
  '
  plain="$(plain_client_request "static-equivalence.example.test" "/static/link.txt" 403)"
  https="$(client_request "static-equivalence.example.test" "/static/link.txt" 403)"
  assert_same_static_response "${plain}" "${https}" '{status, body}'
  assert_response_jq "${plain}" '.body == "forbidden"'

  plain="$(plain_client_request "static-equivalence.example.test" "/static/%2e%2e/outside-secret.txt" 400)"
  https="$(client_request "static-equivalence.example.test" "/static/%2e%2e/outside-secret.txt" 400)"
  assert_same_static_response "${plain}" "${https}" '{status, body}'
  assert_response_jq "${plain}" '.body == "invalid request path"'
}
