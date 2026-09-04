#!/usr/bin/env bash
set -euo pipefail

max_attempts=2
attempt_timeout_seconds=270
kill_after_seconds=5
retry_delay_seconds=5
max_report_bytes=$((10 * 1024 * 1024))

usage() {
  cat >&2 <<'EOF'
usage: tests/scripts/run-pnpm-audit-with-retry.sh <audit-root> <report-output>
EOF
}

if [[ "$#" -ne 2 ]]; then
  usage
  exit 2
fi

audit_root="$1"
report_output="$2"
report_parent="$(dirname -- "${report_output}")"

if [[ ! -d "${audit_root}" ]]; then
  printf 'pnpm audit retry: audit root is not a directory: %s\n' "${audit_root}" >&2
  exit 2
fi
if [[ ! -d "${report_parent}" ]]; then
  printf 'pnpm audit retry: report parent is not a directory: %s\n' "${report_parent}" >&2
  exit 2
fi

for command in jq mktemp mv pnpm rm sleep stat timeout; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    printf 'pnpm audit retry: required command is unavailable: %s\n' "${command}" >&2
    exit 2
  fi
done

umask 077
attempt_report=""

cleanup() {
  if [[ -n "${attempt_report}" ]]; then
    rm -f -- "${attempt_report}"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

report_is_complete() {
  local report="$1"
  local report_bytes

  [[ -f "${report}" ]] || return 1
  report_bytes="$(stat -c '%s' -- "${report}")" || return 1
  ((report_bytes > 0 && report_bytes <= max_report_bytes)) || return 1

  jq -e '
    type == "object" and
    (has("error") | not) and
    (.advisories | type == "object") and
    (.metadata | type == "object")
  ' "${report}" >/dev/null 2>&1
}

report_is_oversized() {
  local report="$1"
  local report_bytes

  [[ -f "${report}" ]] || return 1
  report_bytes="$(stat -c '%s' -- "${report}")" || return 1
  ((report_bytes > max_report_bytes))
}

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  attempt_report="$(mktemp "${report_parent}/.pnpm-audit-attempt-${attempt}.XXXXXX")"
  audit_status=0
  timeout --signal=TERM --kill-after="${kill_after_seconds}s" "${attempt_timeout_seconds}s" \
    pnpm --dir "${audit_root}" audit --audit-level low --json >"${attempt_report}" || audit_status=$?

  if report_is_complete "${attempt_report}"; then
    mv -f -- "${attempt_report}" "${report_output}"
    attempt_report=""
    exit 0
  fi

  if ((attempt == max_attempts)) || report_is_oversized "${attempt_report}"; then
    mv -f -- "${attempt_report}" "${report_output}"
    attempt_report=""
    exit 0
  fi

  rm -f -- "${attempt_report}"
  attempt_report=""
  printf 'pnpm audit retry: incomplete attempt with status %s; retrying in %ss (%s/%s)\n' \
    "${audit_status}" "${retry_delay_seconds}" "${attempt}" "${max_attempts}" >&2
  sleep "${retry_delay_seconds}"
done
