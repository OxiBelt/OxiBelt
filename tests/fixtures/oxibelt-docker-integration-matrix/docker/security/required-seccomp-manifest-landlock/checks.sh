# shellcheck shell=bash
# shellcheck disable=SC2154 # Fixture helpers and proxy_container come from the matrix harness.

run_case_checks() {
  local expected hardening_line logs raw_digest_field response

  response="$(client_request "static.example.test" "/assets/ok.txt" 200)"
  assert_response_jq "${response}" '.body == "hardened static ok\n"'

  logs="$(docker logs "${proxy_container}" 2>&1 || true)"
  hardening_line="$(grep -F 'resolved runtime hardening contract' <<<"${logs}" | tail -n 1 || true)"
  [[ -n "${hardening_line}" ]] \
    || fail_with_diagnostics "catalog-seccomp proxy did not log the resolved hardening contract"
  for expected in \
    '"outcome":"satisfied"' \
    '"requested_mode":"manifest"' \
    '"enforcement":"active"' \
    '"manifest_digest_withheld":true' \
    '"policy_digest_withheld":true' \
    '"verification":"satisfied"' \
    '"assertion_basis":"external_assertion"' \
    '"profile_assertions_match":true' \
    '"profile_identity_kernel_verified":false' \
    '"expected_profile_identity":"oxibelt-tokio-v1"' \
    '"filesystem_manifest_digest_withheld":true'
  do
    if ! grep -F "${expected}" <<<"${hardening_line}" >/dev/null; then
      echo "${logs}" >&2
      fail_with_diagnostics "catalog-seccomp hardening evidence did not contain: ${expected}"
    fi
  done
  for raw_digest_field in \
    '"filesystem_manifest_digest":' \
    '"manifest_digest":' \
    '"policy_digest":'
  do
    if grep -F "${raw_digest_field}" <<<"${hardening_line}" >/dev/null; then
      echo "${logs}" >&2
      fail_with_diagnostics "catalog-seccomp hardening evidence exposed: ${raw_digest_field}"
    fi
  done
  if grep -E 'exited due to signal|signal [0-9]+|SIGSEGV|SIGSYS|segmentation fault' <<<"${logs}" >/dev/null; then
    echo "${logs}" >&2
    fail_with_diagnostics "catalog-seccomp proxy logged a runtime signal failure"
  fi
}
