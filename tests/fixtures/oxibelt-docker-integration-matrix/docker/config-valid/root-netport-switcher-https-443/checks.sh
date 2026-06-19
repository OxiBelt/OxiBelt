
run_case_checks() {
  local response uid
  uid="$(docker exec --user 0 "${proxy_container}" sh -ceu '
for status in /proc/[0-9]*/status; do
  name="$(awk "/^Name:/ { print \$2 }" "${status}")"
  if [ "${name}" = "oxibelt" ]; then
    awk "/^Uid:/ { print \$2 }" "${status}"
    exit 0
  fi
done
exit 1
')"
  if [[ "${uid}" != "10001" ]]; then
    fail_with_diagnostics "expected child oxibelt process to run as UID 10001, got ${uid}"
  fi
  response="$(client_request_on_port 443 "example.test" "/app/netport-switcher" 200)"
  assert_body_jq "${response}" '.upstream == "http-upstream" and .path == "/origin/app/netport-switcher"'
}
