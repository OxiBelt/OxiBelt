served_certificate_sha256() {
  docker run --rm \
    --name "$(unique_docker_container_name "oxibelt-reload-cert-probe")" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint python \
    "${mock_image}" -c '
import hashlib
import socket
import ssl

context = ssl._create_unverified_context()
with socket.create_connection(("proxy", 8443), timeout=5) as connection:
    with context.wrap_socket(connection, server_hostname="proxy") as tls:
        print(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest())
'
}

certificate_file_sha256() {
  openssl x509 -in "$1" -outform DER | openssl dgst -sha256 -r | awk '{print $1}'
}

wait_for_reload_failure() {
  local baseline="$1" logs="" count="" attempt=""
  for ((attempt = 1; attempt <= 30; attempt++)); do
    logs="$(docker logs "${proxy_container}" 2>&1 || true)"
    count="$(grep -F -c 'hot reload failed; keeping previous active state' <<<"${logs}" || true)"
    if ((count > baseline)); then
      return 0
    fi
    sleep 0.5
  done
  echo "${logs}" >&2
  fail_with_diagnostics "combined reload did not reject the invalid WAF candidate"
}

wait_for_served_certificate() {
  local expected="$1" actual="" attempt=""
  for ((attempt = 1; attempt <= 30; attempt++)); do
    actual="$(served_certificate_sha256)"
    if [[ "${actual}" == "${expected}" ]]; then
      return 0
    fi
    sleep 0.5
  done
  fail_with_diagnostics "served downstream certificate did not change after combined reload (expected ${expected}, got ${actual})"
}

run_case_checks() {
  local response="" old_fingerprint="" new_fingerprint="" baseline_failures="" logs=""
  local renewed_cert_dir="${work_dir}/renewed-cert"

  old_fingerprint="$(certificate_file_sha256 "${cert_dir}/fullchain.pem")"
  if [[ "$(served_certificate_sha256)" != "${old_fingerprint}" ]]; then
    fail_with_diagnostics "startup proxy did not serve the expected downstream certificate"
  fi
  response="$(client_request "example.test" "/app/reload" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/reload"'

  mkdir -p "${renewed_cert_dir}"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -days 1 \
    -config "${work_dir}/downstream.cnf" \
    -keyout "${renewed_cert_dir}/privkey.pem" \
    -out "${renewed_cert_dir}/fullchain.pem" >/dev/null 2>&1
  chmod 644 "${renewed_cert_dir}/privkey.pem" "${renewed_cert_dir}/fullchain.pem"
  new_fingerprint="$(certificate_file_sha256 "${renewed_cert_dir}/fullchain.pem")"
  if [[ "${new_fingerprint}" == "${old_fingerprint}" ]]; then
    fail_with_diagnostics "renewed downstream certificate has the startup certificate fingerprint"
  fi

  # The poll interval is long enough to stage one candidate before signalling.
  docker cp "${renewed_cert_dir}/fullchain.pem" "${proxy_container}:/etc/oxibelt/cert/fullchain.pem"
  docker cp "${renewed_cert_dir}/privkey.pem" "${proxy_container}:/etc/oxibelt/cert/privkey.pem"
  docker cp "${case_dir}/config/invalid-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  baseline_failures="$(grep -F -c 'hot reload failed; keeping previous active state' <<<"${logs}" || true)"
  reload_proxy
  wait_for_reload_failure "${baseline_failures}"

  if [[ "$(served_certificate_sha256)" != "${old_fingerprint}" ]]; then
    fail_with_diagnostics "rejected WAF candidate changed the served downstream certificate"
  fi
  response="$(client_request "example.test" "/app/reload" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/reload"'

  docker cp "${case_dir}/config/reloaded-oxibelt.toml" "${proxy_container}:/etc/oxibelt/config/oxibelt.toml"
  reload_proxy
  wait_for_served_certificate "${new_fingerprint}"
  cp "${renewed_cert_dir}/fullchain.pem" "${cert_dir}/fullchain.pem"
  response="$(client_request "example.test" "/app/reload" 403)"
  assert_response_jq "${response}" '.body == "combined hot reload"'
}
