#!/bin/sh
set -eu

rootfs="${1:-}"
target_arch="${2:-}"
config_source="${3:-}"

fail() {
  echo "prepare-alpine-rootfs: $*" >&2
  exit 1
}

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <rootfs> <target-arch> <config-source>" >&2
  exit 2
fi

[ "${rootfs}" = "/opt/oxibelt-rootfs" ] || fail "refusing unexpected rootfs ${rootfs}"
[ -f "${config_source}" ] || fail "configuration source is missing"

case "${target_arch}" in
  amd64) apk_arch=x86_64 ;;
  arm64) apk_arch=aarch64 ;;
  riscv64) apk_arch=riscv64 ;;
  *) fail "unsupported target architecture ${target_arch}" ;;
esac

for marker in \
  "${rootfs}/etc/alpine-release" \
  "${rootfs}/etc/apk/arch" \
  "${rootfs}/etc/apk/repositories" \
  "${rootfs}/lib/apk/db/installed"; do
  [ -f "${marker}" ] || fail "target rootfs marker is missing: ${marker}"
done
[ -d "${rootfs}/etc/apk/keys" ] || fail "target APK signing-key directory is missing"
find "${rootfs}/etc/apk/keys" -type f -name '*.rsa.pub' -size +0c | grep -q . || \
  fail "target APK signing keys are missing"

seed_arch="$(tr -d '[:space:]' <"${rootfs}/etc/apk/arch")"
[ "${seed_arch}" = "${apk_arch}" ] || \
  fail "target rootfs architecture ${seed_arch:-missing} does not match ${apk_arch}"

apk --root "${rootfs}" --arch "${apk_arch}" --no-scripts --no-cache upgrade
apk --root "${rootfs}" --arch "${apk_arch}" --no-scripts --no-cache add \
  ca-certificates libgcc libssl3

for package in alpine-baselayout ca-certificates libgcc libssl3; do
  apk --root "${rootfs}" --arch "${apk_arch}" info --installed "${package}" >/dev/null || \
    fail "required target package is missing: ${package}"
done
[ -s "${rootfs}/etc/ssl/certs/ca-certificates.crt" ] || fail "CA certificate bundle is missing"

for account_file in passwd group shadow; do
  [ -f "${rootfs}/etc/${account_file}" ] || fail "account database ${account_file} is missing"
done
if grep -Eq '^(oxibelt|oxibelt-keysigner):' \
  "${rootfs}/etc/passwd" "${rootfs}/etc/group" "${rootfs}/etc/shadow"; then
  fail "OxiBelt account names already exist in target rootfs"
fi
if awk -F: \
  '$3 == 10001 || $3 == 10002 || $4 == 10001 || $4 == 10002 { found = 1 } END { exit !found }' \
  "${rootfs}/etc/passwd"; then
  fail "OxiBelt account identifiers already exist in target rootfs"
fi
if awk -F: '$3 == 10001 || $3 == 10002 { found = 1 } END { exit !found }' \
  "${rootfs}/etc/group"; then
  fail "OxiBelt account identifiers already exist in target rootfs"
fi

printf '%s\n' \
  'oxibelt:x:10001:10001::/home/oxibelt:/sbin/nologin' \
  'oxibelt-keysigner:x:10002:10002::/home/oxibelt-keysigner:/sbin/nologin' \
  >>"${rootfs}/etc/passwd"
printf '%s\n' \
  'oxibelt:x:10001:oxibelt' \
  'oxibelt-keysigner:x:10002:oxibelt-keysigner' \
  >>"${rootfs}/etc/group"
printf '%s\n' \
  'oxibelt:!:0:0:99999:7:::' \
  'oxibelt-keysigner:!:0:0:99999:7:::' \
  >>"${rootfs}/etc/shadow"

mkdir -p \
  "${rootfs}/app" \
  "${rootfs}/etc/oxibelt/config" \
  "${rootfs}/etc/oxibelt/cert" \
  "${rootfs}/etc/oxibelt/oxirule" \
  "${rootfs}/run/oxibelt-keysigner" \
  "${rootfs}/var/cache/oxibelt"
chown 10001:10001 "${rootfs}/var/cache/oxibelt"
chown 10002:10002 "${rootfs}/run/oxibelt-keysigner"
chmod 0755 \
  "${rootfs}/app" \
  "${rootfs}/etc/oxibelt" \
  "${rootfs}/etc/oxibelt/config" \
  "${rootfs}/etc/oxibelt/cert" \
  "${rootfs}/etc/oxibelt/oxirule" \
  "${rootfs}/var/cache/oxibelt"
chmod 0770 "${rootfs}/run/oxibelt-keysigner"
install -m 0644 "${config_source}" "${rootfs}/etc/oxibelt/config/oxibelt.toml"

# Generate the strict default on the build platform. The strict executable also
# rejects Admin configuration at startup and reload.
awk '
    /^[[:space:]]*\[\[?[[:space:]]*admin([[:space:]]*[.][^][]+)*[[:space:]]*\]\]?[[:space:]]*(#.*)?$/ { drop_admin = 1; next }
    /^[[:space:]]*\[/ { drop_admin = 0 }
    !drop_admin { print }
  ' "${config_source}" >/opt/oxibelt-strict.toml
if grep -Eq '^[[:space:]]*\[\[?[[:space:]]*admin([[:space:]]*[.]|[[:space:]]*\])' \
  /opt/oxibelt-strict.toml; then
  fail "strict configuration still contains an Admin table"
fi
chmod 0644 /opt/oxibelt-strict.toml
