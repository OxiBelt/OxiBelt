#!/usr/bin/env bash

run_case_checks() {
  local peer="oxibelt-pq-openssl-server-${run_id}"
  local response=""
  docker create --name "${peer}" --label "${test_label}" --network "${network_name}" \
    --network-alias openssl-pq --entrypoint openssl "${pq_probe_image}" \
    s_server -accept 8443 -cert /tmp/server.pem -key /tmp/server.key \
    -tls1_3 -groups SecP256r1MLKEM768 -www >/dev/null
  docker cp "${cert_dir}/fullchain.pem" "${peer}:/tmp/server.pem"
  docker cp "${cert_dir}/privkey.pem" "${peer}:/tmp/server.key"
  docker start "${peer}" >/dev/null

  # The independent peer accepts only 0x11eb. The opted-in upstream must work,
  # while the default upstream to exactly the same peer must fail TLS admission.
  response="$(client_request_with_sni "example.test" "example.test" "/pq-enabled" 200)"
  assert_response_jq "${response}" '.status == 200'
  response="$(client_request_with_sni "example.test" "example.test" "/pq-disabled" 502)"
  assert_response_jq "${response}" '.status == 502'
}
