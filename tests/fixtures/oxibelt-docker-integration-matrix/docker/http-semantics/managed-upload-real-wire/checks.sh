run_case_checks() {
  local protocol client_container output status

  for protocol in h1 h2 h3; do
    client_container="$(unique_docker_container_name "oxibelt-managed-upload-${protocol}")"
    docker create \
      --name "${client_container}" \
      --label "${test_label}" \
      --network "${network_name}" \
      "${protocol_probe_image}" \
      managed-upload-client \
      --protocol "${protocol}" \
      --host proxy \
      --port 8443 \
      --server-name proxy \
      --authority example.test:8443 \
      --creation-path /submit \
      --ca-cert /tmp/probe-ca.pem \
      --client-cert /tmp/client.pem \
      --client-key /tmp/client.key \
      --wrong-client-cert /tmp/wrong-client.pem \
      --wrong-client-key /tmp/wrong-client.key >/dev/null
    docker cp "${cert_dir}/fullchain.pem" "${client_container}:/tmp/probe-ca.pem"
    docker cp "${client_tls_dir}/client.pem" "${client_container}:/tmp/client.pem"
    docker cp "${client_tls_dir}/client.key" "${client_container}:/tmp/client.key"
    docker cp "${client_tls_dir}/client-second.pem" "${client_container}:/tmp/wrong-client.pem"
    docker cp "${client_tls_dir}/client-second.key" "${client_container}:/tmp/wrong-client.key"
    status=0
    output="$(docker_start_stdout_only "${client_container}")" || status=$?
    if [[ "${status}" != "0" ]]; then
      append_container_stderr "${client_container}"
      echo "${output}" >&2
      docker rm -f "${client_container}" >/dev/null 2>&1 || true
      fail_with_diagnostics "managed-upload ${protocol} wire lifecycle failed"
    fi
    grep -Fx "managed-upload-wire-ok protocol=${protocol}" <<<"${output}" >/dev/null \
      || fail_with_diagnostics "managed-upload ${protocol} wire probe omitted success receipt"
    docker rm -f "${client_container}" >/dev/null
  done
}
