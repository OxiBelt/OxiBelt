
run_case_checks() {
  local response output kernel_container
  response="$(client_request "example.test" "/app/kernel-extension" 200)"
  assert_body_jq "${response}" '.path == "/origin/app/kernel-extension"'

  kernel_container="oxibelt-kernel-extension-${run_id}-${RANDOM}"
  docker create \
    --name "${kernel_container}" \
    --label "${test_label}" \
    --network "${network_name}" \
    --entrypoint /bin/sh \
    "${proxy_image}" \
    -ceu '
      mkdir -p /tmp/oxibelt-root
      /bin/sh /tmp/kernel-extension/install.sh --apply --root /tmp/oxibelt-root --kernel-release 7.0.3
      /bin/sh /tmp/kernel-extension/verify.sh --root /tmp/oxibelt-root --kernel-release 7.0.3
      limits_file=/tmp/oxibelt-root/etc/security/limits.d/90-oxibelt-edge.conf
      if awk '"'"'$1 == "*" && $3 == "nofile" { found = 1 } END { exit found ? 0 : 1 }'"'"' "${limits_file}"; then
        echo "${limits_file} grants nofile limits to wildcard principal *" >&2
        exit 45
      fi
      grep -Fx "oxibelt soft nofile 1048576" "${limits_file}" >/dev/null
      grep -Fx "oxibelt hard nofile 1048576" "${limits_file}" >/dev/null
      if /bin/sh /tmp/kernel-extension/install.sh --dry-run --root /tmp/old-root --kernel-release 6.19.14 >/tmp/old-kernel.log 2>&1; then
        cat /tmp/old-kernel.log >&2
        exit 44
      fi
      grep -F "targets Linux 7.0.x" /tmp/old-kernel.log >/dev/null
    ' >/dev/null
  docker cp "${repo_root}/kernel-extension" "${kernel_container}:/tmp/kernel-extension"

  if ! output="$(docker start -a "${kernel_container}" 2>&1)"; then
    echo "${output}" >&2
    docker rm -f "${kernel_container}" >/dev/null 2>&1 || true
    fail_with_diagnostics "kernel extension installer container failed"
  fi
  docker rm -f "${kernel_container}" >/dev/null 2>&1 || true
  if ! grep -F "verified /tmp/oxibelt-root/etc/sysctl.d/90-oxibelt-edge.conf" <<<"${output}" >/dev/null; then
    echo "${output}" >&2
    fail_with_diagnostics "kernel extension verifier did not report sysctl template"
  fi
}
