#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tests/scripts/retry-docker-pull.sh <image>
EOF
}

if [[ "$#" -ne 1 ]]; then
  usage
  exit 2
fi

image="$1"

retry_command() {
  local attempts="$1"
  shift
  local delay=5
  local attempt status

  for attempt in $(seq 1 "${attempts}"); do
    if "$@"; then
      return 0
    fi
    status=$?
    if [[ "${attempt}" == "${attempts}" ]]; then
      return "${status}"
    fi
    printf 'Command failed with status %s; retrying in %ss (%s/%s): %s\n' \
      "${status}" "${delay}" "${attempt}" "${attempts}" "$*" >&2
    sleep "${delay}"
    delay=$((delay * 2))
  done
}

retry_command 3 docker pull "${image}"
