#!/usr/bin/env bash
# Validate the chart-owned edge-secure-medium v1 profile renderer without
# creating Kubernetes resources or handling Secret material.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
profile_values="${chart_dir}/examples/edge-secure-medium-v1-values.yaml"
temp_root="${TMPDIR:-/tmp}"
work_dir=""

die() {
  echo "Helm edge-secure-medium profile check: $*" >&2
  exit 1
}

require_command() {
  local command="$1"
  command -v "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
}

cleanup() {
  local status="$?"
  set +e

  case "${work_dir}" in
    "${temp_root%/}"/oxibelt-helm-edge-secure-medium.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Helm edge-secure-medium work directory: ${work_dir}" >&2
      ;;
  esac

  exit "${status}"
}
trap cleanup EXIT

render() {
  local name="$1"
  shift
  helm template oxibelt "${chart_dir}" "$@" >"${work_dir}/${name}.yaml"
}

expect_failure() {
  local name="$1"
  shift

  if helm template oxibelt "${chart_dir}" "$@" >"${work_dir}/${name}.log" 2>&1; then
    die "${name} unexpectedly rendered successfully"
  fi
}

expect_failure_contains() {
  local name="$1"
  local expected="$2"
  shift 2

  expect_failure "${name}" "$@"
  grep -F -- "${expected}" "${work_dir}/${name}.log" >/dev/null \
    || die "${name} did not report the expected validation failure: ${expected}"
}

assert_contains() {
  local file="$1"
  local expected="$2"
  grep -F -- "${expected}" "${file}" >/dev/null \
    || die "$(basename "${file}") is missing: ${expected}"
}

assert_not_contains() {
  local file="$1"
  local unexpected="$2"
  if grep -F -- "${unexpected}" "${file}" >/dev/null; then
    die "$(basename "${file}") unexpectedly contains: ${unexpected}"
  fi
}

assert_following_line() {
  local file="$1"
  local heading="$2"
  local expected="$3"

  grep -F -A 1 -- "${heading}" "${file}" | grep -F -- "${expected}" >/dev/null \
    || die "$(basename "${file}") does not render ${expected} after ${heading}"
}

for command in helm grep mktemp; do
  require_command "${command}"
done

[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
[[ -f "${profile_values}" ]] || die "profile values preset is unavailable: ${profile_values}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-edge-secure-medium.XXXXXX")"

helm lint --strict "${chart_dir}" >"${work_dir}/lint-default.log"
helm lint --strict "${chart_dir}" -f "${profile_values}" >"${work_dir}/lint-profile.log"

render defaults
assert_not_contains "${work_dir}/defaults.yaml" "profile = \"edge-secure-medium\""
assert_not_contains "${work_dir}/defaults.yaml" "profile_version = 1"
assert_not_contains "${work_dir}/defaults.yaml" "quic-host-key.b64"
assert_not_contains "${work_dir}/defaults.yaml" "terminationGracePeriodSeconds:"

render public_tls_names \
  --set-string tls.serverNames[0]=public.example.test
assert_contains "${work_dir}/public_tls_names.yaml" "server_names = [\"public.example.test\"]"
assert_contains "${work_dir}/public_tls_names.yaml" "require_sni = true"
assert_contains "${work_dir}/public_tls_names.yaml" "reject_unknown_sni = true"
assert_not_contains "${work_dir}/public_tls_names.yaml" "profile = \"edge-secure-medium\""

render profile_enforcing -f "${profile_values}"
assert_contains "${work_dir}/profile_enforcing.yaml" "profile = \"edge-secure-medium\""
assert_contains "${work_dir}/profile_enforcing.yaml" "profile_version = 1"
assert_contains "${work_dir}/profile_enforcing.yaml" "[waf]"
assert_following_line "${work_dir}/profile_enforcing.yaml" "[waf]" "enabled = true"
assert_contains "${work_dir}/profile_enforcing.yaml" "mode = \"enforcing\""
assert_contains "${work_dir}/profile_enforcing.yaml" "server_names = [\"edge.example.test\"]"
assert_contains "${work_dir}/profile_enforcing.yaml" "host_key_file = \"quic-host-key.b64\""
assert_contains "${work_dir}/profile_enforcing.yaml" "detail = \"detailed\""
assert_following_line "${work_dir}/profile_enforcing.yaml" "[overload]" "enabled = true"
assert_contains "${work_dir}/profile_enforcing.yaml" "name: oxibelt-quic-host-key"
assert_contains "${work_dir}/profile_enforcing.yaml" "path: quic-host-key.b64"
assert_contains "${work_dir}/profile_enforcing.yaml" "terminationGracePeriodSeconds: 360"
assert_not_contains "${work_dir}/profile_enforcing.yaml" "# Source: oxibelt/templates/admin-service.yaml"

render profile_monitor -f "${profile_values}" --set-string operationalProfile.wafMode=monitor
assert_contains "${work_dir}/profile_monitor.yaml" "mode = \"monitor\""
enforcing_checksum="$(grep -m 1 -F "checksum/oxibelt-config:" "${work_dir}/profile_enforcing.yaml")"
monitor_checksum="$(grep -m 1 -F "checksum/oxibelt-config:" "${work_dir}/profile_monitor.yaml")"
[[ "${enforcing_checksum}" != "${monitor_checksum}" ]] \
  || die "changing the profile-derived WAF mode did not change the generated configuration digest"

render profile_daemonset -f "${profile_values}" --set-string workload.kind=DaemonSet
assert_contains "${work_dir}/profile_daemonset.yaml" "kind: DaemonSet"
assert_contains "${work_dir}/profile_daemonset.yaml" "name: oxibelt-quic-host-key"
assert_contains "${work_dir}/profile_daemonset.yaml" "path: quic-host-key.b64"
assert_contains "${work_dir}/profile_daemonset.yaml" "readOnly: true"
assert_contains "${work_dir}/profile_daemonset.yaml" "terminationGracePeriodSeconds: 360"

expect_failure_contains profile_external_config \
  "operationalProfile.name requires chart-owned config.create=true with no config.existingConfigMap" \
  -f "${profile_values}" \
  --set config.create=false \
  --set-string config.existingConfigMap=operator-managed-base \
  --set-string config.existingConfigMapDigest=1111111111111111111111111111111111111111111111111111111111111111

expect_failure_contains profile_missing_server_names \
  "operationalProfile edge-secure-medium requires tls.serverNames" \
  --set-string operationalProfile.name=edge-secure-medium \
  --set operationalProfile.version=1 \
  --set lifecycle.terminationGracePeriodSeconds=360 \
  --set-string quic.hostKeySecretName=oxibelt-quic-host-key

expect_failure_contains profile_missing_quic_host_key \
  "operationalProfile edge-secure-medium requires quic.hostKeySecretName" \
  --set-string operationalProfile.name=edge-secure-medium \
  --set operationalProfile.version=1 \
  --set lifecycle.terminationGracePeriodSeconds=360 \
  --set-string tls.serverNames[0]=edge.example.test

expect_failure_contains profile_short_grace \
  "operationalProfile edge-secure-medium requires lifecycle.terminationGracePeriodSeconds of at least 340" \
  -f "${profile_values}" \
  --set lifecycle.terminationGracePeriodSeconds=339

expect_failure_contains profile_unsupported_version \
  "operationalProfile edge-secure-medium supports only version 1" \
  -f "${profile_values}" \
  --set operationalProfile.version=2

expect_failure_contains profile_metrics_disabled \
  "operationalProfile edge-secure-medium requires metrics.enabled=true" \
  -f "${profile_values}" \
  --set metrics.enabled=false

expect_failure_contains profile_admin_enabled \
  "operationalProfile edge-secure-medium keeps admin.enabled=false because the chart does not render the required IPM and durable audit configuration" \
  -f "${profile_values}" \
  --skip-schema-validation \
  --set admin.enabled=true

expect_failure_contains shared_tls_and_quic_secret \
  "quic.hostKeySecretName must differ from tls.secretName so the host key remains narrowly projected" \
  --set-string quic.hostKeySecretName=oxibelt-tls

expect_failure unknown_profile_schema \
  --set-string operationalProfile.name=unsupported-profile
expect_failure_contains unknown_profile_helper \
  "operationalProfile.name must be edge-secure-medium" \
  --skip-schema-validation \
  --set-string operationalProfile.name=unsupported-profile

echo "Helm edge-secure-medium profile check passed"
