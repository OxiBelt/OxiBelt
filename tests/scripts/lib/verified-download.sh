#!/usr/bin/env bash
# Provides a bounded, fail-closed download primitive for pinned CI assets.

download_verified_sha256() (
  set -euo pipefail

  if [[ "$#" -ne 3 ]]; then
    echo "usage: download_verified_sha256 <url> <sha256> <destination>" >&2
    exit 2
  fi

  local url="$1"
  local expected_sha256="$2"
  local destination="$3"
  local destination_parent
  local staging=""

  [[ "${expected_sha256}" =~ ^[a-f0-9]{64}$ ]] || {
    echo "refusing download with an invalid SHA-256 digest" >&2
    exit 2
  }
  [[ "${destination}" = /* ]] || {
    echo "download destination must be an absolute path" >&2
    exit 2
  }
  [[ ! -e "${destination}" && ! -L "${destination}" ]] || {
    echo "refusing to replace existing download destination" >&2
    exit 2
  }

  destination_parent="$(dirname -- "${destination}")"
  [[ -d "${destination_parent}" && ! -L "${destination_parent}" ]] || {
    echo "download destination parent must be a real directory" >&2
    exit 2
  }

  if ! staging="$(mktemp "${destination}.partial.XXXXXX")"; then
    echo "could not create a private download staging file" >&2
    exit 1
  fi
  trap 'rm -f -- "${staging}" || true' EXIT
  trap 'exit 1' HUP INT TERM

  if ! curl --fail --location --silent --show-error \
    --retry 8 --retry-all-errors --connect-timeout 10 --max-time 60 --retry-max-time 300 \
    --output "${staging}" "${url}"; then
    echo "pinned asset download failed after bounded retries" >&2
    exit 1
  fi

  if ! printf '%s  %s\n' "${expected_sha256}" "${staging}" | sha256sum --check --status; then
    echo "downloaded asset did not match its pinned SHA-256 digest" >&2
    exit 1
  fi

  if ! mv -T --no-clobber -- "${staging}" "${destination}" \
    || [[ -e "${staging}" || -L "${staging}" ]]; then
    echo "refusing to publish over an existing download destination" >&2
    exit 1
  fi
  staging=""
  trap - EXIT HUP INT TERM
)
