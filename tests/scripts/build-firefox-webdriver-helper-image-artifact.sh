#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tests/scripts/build-firefox-webdriver-helper-image-artifact.sh <docker-platform> <output-dir>
EOF
}

platform="${1:-}"
output_dir="${2:-}"

if [[ "${platform}" != "linux/amd64" || -z "${output_dir}" ]]; then
  usage
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
firefox_version="154.0"
firefox_sha256="7665cd49ab13417270748325838e565136adbc76d41bbd76fb24d15a0cc7792b"
geckodriver_version="0.37.1"
geckodriver_sha256="e815130ea95983e162ae91843b48d3a3ce991735635fce83a647afde21e09f7e"
base_image="docker.io/library/debian:trixie-slim@sha256:abc9cb88a5587630d7f915f47b23b0668fe250fbfc6457aa4d52b534c1bbf73f"
firefox_image="oxibelt/firefox-webdriver:${firefox_version}-geckodriver-${geckodriver_version}"
image_tar="${output_dir%/}/oxibelt-firefox-webdriver-image.tar"

retry_command() {
  local attempts="$1"
  shift
  local delay=5
  local attempt status

  for attempt in $(seq 1 "${attempts}"); do
    "$@" && return 0
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

mkdir -p "${output_dir}"

retry_command 3 docker pull --platform "${platform}" "${base_image}"
retry_command 3 docker buildx build \
  --platform "${platform}" \
  --build-arg "DEBIAN_IMAGE=${base_image}" \
  --build-arg "FIREFOX_VERSION=${firefox_version}" \
  --build-arg "FIREFOX_SHA256=${firefox_sha256}" \
  --build-arg "GECKODRIVER_VERSION=${geckodriver_version}" \
  --build-arg "GECKODRIVER_SHA256=${geckodriver_sha256}" \
  --file "${repo_root}/tests/docker/firefox_webdriver/Dockerfile" \
  --tag "${firefox_image}" \
  --load \
  "${repo_root}/tests/docker/firefox_webdriver"

docker run --rm \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001,mode=1777 \
  --entrypoint /bin/sh \
  "${firefox_image}" -ceu '
  test "$(id -u)" = "10001"
  test "$(/opt/firefox/firefox --version)" = "Mozilla Firefox 154.0"
  /usr/local/bin/geckodriver --version | grep --fixed-strings -- "geckodriver 0.37.1 "
  command -v certutil
  command -v zip
  command -v curl
'
retry_command 3 docker save --output "${image_tar}" "${firefox_image}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "image_tar=$(basename "${image_tar}")"
    echo "image_tag=${firefox_image}"
  } >>"${GITHUB_OUTPUT}"
fi

echo "Wrote ${image_tar}"
