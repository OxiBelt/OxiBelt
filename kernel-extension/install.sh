#!/bin/sh
set -eu

usage() {
  cat >&2 <<'USAGE'
usage: install.sh [--dry-run|--apply] [--root DIR] [--force] [--kernel-release RELEASE]
USAGE
}

mode="dry-run"
root="/"
force="0"
kernel_release="$(uname -r)"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      mode="dry-run"
      shift
      ;;
    --apply)
      mode="apply"
      shift
      ;;
    --root)
      [ "$#" -ge 2 ] || {
        usage
        exit 2
      }
      root="$2"
      shift 2
      ;;
    --force)
      force="1"
      shift
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

if ! kernel_at_least_7 "$kernel_release" && [ "$force" != "1" ]; then
  echo "OxiBelt kernel extension targets Linux 7.0.x or newer; detected ${kernel_release}" >&2
  echo "Use --force only if this host has equivalent backported networking behavior." >&2
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

install_file() {
  src="$1"
  dest="$2"
  if [ "$mode" = "dry-run" ]; then
    echo "would install ${src} -> ${dest}"
    return 0
  fi
  if [ -e "$dest" ] && [ "$force" != "1" ]; then
    echo "${dest} already exists; use --force to replace it" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
  chmod 0644 "$dest"
  echo "installed ${dest}"
}

sysctl_dest="$(target_path /etc/sysctl.d/90-oxibelt-edge.conf)"
limits_dest="$(target_path /etc/security/limits.d/90-oxibelt-edge.conf)"
systemd_dest="$(target_path /etc/systemd/system/oxibelt.service.d/10-limits.conf)"

install_file "$script_dir/templates/sysctl.d/90-oxibelt-edge.conf" "$sysctl_dest"
install_file "$script_dir/templates/limits.d/90-oxibelt-edge.conf" "$limits_dest"
install_file "$script_dir/templates/systemd/oxibelt.service.d/10-limits.conf" "$systemd_dest"

if [ "$mode" = "apply" ] && [ "$root" = "/" ] && command -v sysctl >/dev/null 2>&1; then
  sysctl --system >/dev/null
  echo "applied sysctl configuration"
fi
