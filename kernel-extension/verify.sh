#!/bin/sh
set -eu

usage() {
  cat >&2 <<'USAGE'
usage: verify.sh [--root DIR] [--kernel-release RELEASE]
USAGE
}

root="/"
kernel_release="$(uname -r)"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --root)
      [ "$#" -ge 2 ] || {
        usage
        exit 2
      }
      root="$2"
      shift 2
      ;;
    --kernel-release)
      [ "$#" -ge 2 ] || {
        usage
        exit 2
      }
      kernel_release="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

script_dir="$(CDPATH= cd "$(dirname "$0")" && pwd)"

kernel_at_least_7() {
  version_core=${1%%-*}
  old_ifs=$IFS
  IFS=.
  set -- $version_core
  IFS=$old_ifs
  major=${1:-0}
  minor=${2:-0}
  case "$major:$minor" in
    *[!0-9:]*)
      return 1
      ;;
  esac
  [ "$major" -gt 7 ] || { [ "$major" -eq 7 ] && [ "$minor" -ge 0 ]; }
}

if ! kernel_at_least_7 "$kernel_release"; then
  echo "OxiBelt kernel extension targets Linux 7.0.x or newer; detected ${kernel_release}" >&2
  exit 1
fi

target_path() {
  case "$root" in
    /)
      printf '%s\n' "$1"
      ;;
    *)
      printf '%s/%s\n' "${root%/}" "${1#/}"
      ;;
  esac
}

verify_file() {
  src="$1"
  dest="$2"
  if [ ! -f "$dest" ]; then
    echo "missing ${dest}" >&2
    exit 1
  fi
  if ! cmp -s "$src" "$dest"; then
    echo "${dest} does not match OxiBelt template" >&2
    exit 1
  fi
  echo "verified ${dest}"
}

verify_file "$script_dir/templates/sysctl.d/90-oxibelt-edge.conf" "$(target_path /etc/sysctl.d/90-oxibelt-edge.conf)"
verify_file "$script_dir/templates/limits.d/90-oxibelt-edge.conf" "$(target_path /etc/security/limits.d/90-oxibelt-edge.conf)"
verify_file "$script_dir/templates/systemd/oxibelt.service.d/10-limits.conf" "$(target_path /etc/systemd/system/oxibelt.service.d/10-limits.conf)"

if [ "$root" = "/" ] && [ -r /proc/sys/net/core/somaxconn ]; then
  echo "runtime net.core.somaxconn=$(cat /proc/sys/net/core/somaxconn)"
fi
