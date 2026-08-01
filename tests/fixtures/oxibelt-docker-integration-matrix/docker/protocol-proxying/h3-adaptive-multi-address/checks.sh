# shellcheck shell=bash
# shellcheck disable=SC2154 # Sourced by run-proxy-integration-matrix.sh.

run_case_checks() {
  local first second third first_id second_id third_id before after
  mock_dns_control RESET >/dev/null

  first="$(protocol_probe_client "h2" "example.test" "/app/adaptive-first" 200)"
  second="$(protocol_probe_client "h2" "example.test" "/app/adaptive-second" 200)"
  first_id="$(jq -r '.body | fromjson | .connection_id' <<<"${first}")"
  second_id="$(jq -r '.body | fromjson | .connection_id' <<<"${second}")"
  [[ "${first_id}" == "${second_id}" ]] \
    || fail_with_diagnostics "adaptive H3 connection was not reused within DNS TTL"

  before="$(mock_dns_control STATS | jq -r '.query_count')"
  [[ "${before}" -le 2 ]] \
    || fail_with_diagnostics "adaptive H3 resolver repeated DNS within the effective TTL"

  sleep 2
  mock_dns_control REVERSE >/dev/null
  third="$(protocol_probe_client "h2" "example.test" "/app/adaptive-reordered" 200)"
  third_id="$(jq -r '.body | fromjson | .connection_id' <<<"${third}")"
  [[ "${first_id}" == "${third_id}" ]] \
    || fail_with_diagnostics "DNS answer reordering churned a healthy H3 connection"

  after="$(mock_dns_control STATS | jq -r '.query_count')"
  [[ "${after}" -gt "${before}" ]] \
    || fail_with_diagnostics "expired H3 resolver state did not refresh after answer reordering"
}
