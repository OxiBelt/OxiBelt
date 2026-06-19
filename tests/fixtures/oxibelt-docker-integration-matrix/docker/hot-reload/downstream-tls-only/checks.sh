
run_case_checks() {
  local response
  response="$(client_request "example.test" "/app/tls-before" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/tls-before"'

  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -days 1 \
    -config "${work_dir}/downstream.cnf" \
    -keyout "${cert_dir}/privkey.pem" \
    -out "${cert_dir}/fullchain.pem" >/dev/null 2>&1
  chmod 644 "${cert_dir}/privkey.pem" "${cert_dir}/fullchain.pem"
  docker cp "${cert_dir}/fullchain.pem" "${proxy_container}:/etc/oxibelt/cert/fullchain.pem"
  docker cp "${cert_dir}/privkey.pem" "${proxy_container}:/etc/oxibelt/cert/privkey.pem"
  reload_proxy

  response="$(client_request "example.test" "/app/tls-after" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/tls-after"'
}
