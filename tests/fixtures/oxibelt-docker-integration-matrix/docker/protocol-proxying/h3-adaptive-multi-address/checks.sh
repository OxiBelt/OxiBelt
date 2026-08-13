# shellcheck shell=bash
# shellcheck disable=SC2154 # Sourced by run-proxy-integration-matrix.sh.

bounded_dns_stats() {
  mock_dns_control STATS | jq -c \
    '{query_count, a_query_count, aaaa_query_count, reverse_answers}'
}

report_dns_stats_failure() {
  local reason="$1" before_stats="$2" after_stats="$3"
  local before_total before_a before_aaaa after_total after_a after_aaaa
  local diagnostics

  before_total="$(jq -r '.query_count // "unavailable"' <<<"${before_stats:-null}")"
  before_a="$(jq -r '.a_query_count // "unavailable"' <<<"${before_stats:-null}")"
  before_aaaa="$(jq -r '.aaaa_query_count // "unavailable"' <<<"${before_stats:-null}")"
  after_total="$(jq -r '.query_count // "unavailable"' <<<"${after_stats:-null}")"
  after_a="$(jq -r '.a_query_count // "unavailable"' <<<"${after_stats:-null}")"
  after_aaaa="$(jq -r '.aaaa_query_count // "unavailable"' <<<"${after_stats:-null}")"
  diagnostics=$(cat <<EOF
reason=${reason}
before: total=${before_total} A=${before_a} AAAA=${before_aaaa}
before_json=${before_stats:-unavailable}
after: total=${after_total} A=${after_a} AAAA=${after_aaaa}
after_json=${after_stats:-unavailable}
EOF
)

  printf '%s\n' "${diagnostics}" >&2
  if [[ -n "${logs_dir:-}" ]]; then
    mkdir -p "${logs_dir}" 2>/dev/null || true
    printf '%s\n' "${diagnostics}" \
      >"${logs_dir}/h3-adaptive-multi-address-dns-stats.log" 2>/dev/null || true
  fi
  fail_with_diagnostics "${reason} (DNS stats: before total=${before_total}, A=${before_a}, AAAA=${before_aaaa}; after total=${after_total}, A=${after_a}, AAAA=${after_aaaa})"
}

run_case_checks() {
  local first second third first_id second_id third_id before after
  local before_stats after_stats
  mock_dns_control RESET >/dev/null

  first="$(protocol_probe_client "h2" "example.test" "/app/adaptive-first" 200)"
  second="$(protocol_probe_client "h2" "example.test" "/app/adaptive-second" 200)"
  first_id="$(jq -r '.body | fromjson | .connection_id' <<<"${first}")"
  second_id="$(jq -r '.body | fromjson | .connection_id' <<<"${second}")"
  before_stats="$(bounded_dns_stats)"
  before="$(jq -r '.query_count' <<<"${before_stats}")"
  [[ "${first_id}" == "${second_id}" ]] \
    || report_dns_stats_failure \
      "adaptive H3 connection was not reused within DNS TTL" \
      "${before_stats}" "${after_stats:-}"

  [[ "${before}" -le 2 ]] \
    || report_dns_stats_failure \
      "adaptive H3 resolver repeated DNS within the effective TTL" \
      "${before_stats}" "${after_stats:-}"

  sleep 11
  mock_dns_control REVERSE >/dev/null
  third="$(protocol_probe_client "h2" "example.test" "/app/adaptive-reordered" 200)"
  third_id="$(jq -r '.body | fromjson | .connection_id' <<<"${third}")"
  after_stats="$(bounded_dns_stats)"
  after="$(jq -r '.query_count' <<<"${after_stats}")"
  [[ "${first_id}" == "${third_id}" ]] \
    || report_dns_stats_failure \
      "DNS answer reordering churned a healthy H3 connection" \
      "${before_stats}" "${after_stats}"

  [[ "${after}" -gt "${before}" ]] \
    || report_dns_stats_failure \
      "expired H3 resolver state did not refresh after answer reordering" \
      "${before_stats}" "${after_stats}"
}
