
run_case_checks() {
  local first revalidated escaped body

  first="$(client_request "static-hot-cache.example.test" "/static/hot.txt" 200)"
  assert_response_jq "${first}" '.body == "hot cache v1\n"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu \
    'printf "hot cache v2\n" > /etc/oxibelt/config/public/hot.txt'
  revalidated="$(client_request "static-hot-cache.example.test" "/static/hot.txt" 200)"
  assert_response_jq "${revalidated}" '.body == "hot cache v2\n"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu '
    rm -f /etc/oxibelt/config/public/hot.txt
    ln -s /etc/oxibelt/config/outside-secret.txt /etc/oxibelt/config/public/hot.txt
  '
  escaped="$(client_request_with_headers_to_target "proxy" 8443 "static-hot-cache.example.test" "/static/hot.txt" "403,404" "GET" "")"
  body="$(jq -r '.body' <<<"${escaped}")"
  if grep -F "STATIC_HOT_CACHE_SECRET" <<<"${body}" >/dev/null; then
    echo "${escaped}" >&2
    fail_with_diagnostics "static hot cache served an out-of-root symlink target"
  fi
}
