#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
cd "${repo_root}"

forbidden_pattern='^(k8s-openapi|kube|sequoia-openpgp|oxibeltctl|oxibelt-gateway-controller|oxibelt-deployment-diagnostics) v'

check_profile() {
  local label="$1"
  shift

  cargo check -p oxibelt --lib --bin oxibelt --locked "$@"
  cargo test -p oxibelt --test package_boundaries --locked "$@"

  local tree
  tree="$(cargo tree -p oxibelt --locked -e normal --prefix none --format '{p}' "$@")"
  if grep -Eq "${forbidden_pattern}" <<<"${tree}"; then
    echo "oxibelt ${label} dependency graph contains a forbidden control-plane package:" >&2
    grep -E "${forbidden_pattern}" <<<"${tree}" | sort -u >&2
    exit 1
  fi

  echo "OxiBelt ${label} data-plane package boundary passed."
}

check_profile "default-feature"
check_profile "all-feature" --all-features
