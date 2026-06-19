
run_case_checks() {
  local response swapper_pid worker_pids failed

  response="$(client_request "static.example.test" "/static/ok.txt" 200)"
  assert_response_jq "${response}" '.body == "static ok\n"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu '
    rm -f /etc/oxibelt/config/public/direct.txt
    ln -s /etc/oxibelt/config/outside-secret.txt /etc/oxibelt/config/public/direct.txt
  '
  response="$(client_request "static.example.test" "/static/direct.txt" 403)"
  assert_response_jq "${response}" '.body == "forbidden"'

  docker exec --user 0 "${proxy_container}" /bin/sh -ceu '
    while :; do
      printf "race safe body\n" > /etc/oxibelt/config/public/race.tmp
      mv /etc/oxibelt/config/public/race.tmp /etc/oxibelt/config/public/race.txt
      rm -f /etc/oxibelt/config/public/race.txt
      ln -s /etc/oxibelt/config/outside-secret.txt /etc/oxibelt/config/public/race.txt
      sleep 0.01
      rm -f /etc/oxibelt/config/public/race.txt
    done
  ' &
  swapper_pid=$!
  worker_pids=()
  failed=0

  for worker in $(seq 1 4); do
    (
      local index response status
      for index in $(seq 1 50); do
        response="$(client_request_with_headers_to_target "proxy" 8443 "static.example.test" "/static/race.txt" "200,403,404" "GET" "")"
        if jq -e '.body | contains("STATIC_RACE_SECRET")' <<<"${response}" >/dev/null; then
          echo "${response}" >&2
          exit 1
        fi
        status="$(jq -r '.status' <<<"${response}")"
        if [[ "${status}" == "200" ]] && ! jq -e '.body == "race safe body\n"' <<<"${response}" >/dev/null; then
          echo "${response}" >&2
          exit 1
        fi
      done
    ) &
    worker_pids+=("$!")
  done

  for pid in "${worker_pids[@]}"; do
    if ! wait "${pid}"; then
      failed=1
    fi
  done

  kill "${swapper_pid}" >/dev/null 2>&1 || true
  wait "${swapper_pid}" >/dev/null 2>&1 || true

  if [[ "${failed}" != "0" ]]; then
    fail_with_diagnostics "static symlink race leaked or served unexpected content"
  fi
}
