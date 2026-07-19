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

cargo check \
  -p oxibelt-dataplane-strict \
  --bin oxibelt-dataplane-strict \
  --locked \
  --no-default-features

strict_tree="$(cargo tree \
  -p oxibelt-dataplane-strict \
  --locked \
  --no-default-features \
  -e features \
  --prefix none)"
if grep -Fq 'oxibelt feature "admin-runtime"' <<<"${strict_tree}"; then
  echo "strict data-plane dependency graph enabled oxibelt/admin-runtime" >&2
  grep -F 'oxibelt feature "admin-runtime"' <<<"${strict_tree}" >&2
  exit 1
fi

strict_metadata="$(cargo metadata --locked --no-deps --format-version 1)"
strict_targets="$(jq -r '
  .packages[]
  | select(.name == "oxibelt-dataplane-strict")
  | .targets[]
  | select(.kind == ["bin"])
  | .name
' <<<"${strict_metadata}")"
if [[ "${strict_targets}" != "oxibelt-dataplane-strict" ]]; then
  echo "strict data-plane package must expose exactly one production binary" >&2
  printf '%s\n' "${strict_targets}" >&2
  exit 1
fi

echo "OxiBelt strict data-plane package boundary passed."
