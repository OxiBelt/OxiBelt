#!/usr/bin/env bash
# Validate OxiBelt's portable NetworkPolicy and optional Cilium FQDN renderer
# without creating Kubernetes resources or handling Secret material.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
secure_values="${chart_dir}/examples/edge-secure-medium-v1-values.yaml"
admin_values="${chart_dir}/examples/admin-mtls-values.yaml"
temp_root="${TMPDIR:-/tmp}"
work_dir=""

die() {
  echo "Helm NetworkPolicy check: $*" >&2
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
    "${temp_root%/}"/oxibelt-helm-network-policy.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Helm NetworkPolicy work directory: ${work_dir}" >&2
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

assert_count() {
  local file="$1"
  local expected="$2"
  local expected_count="$3"
  local actual_count

  actual_count="$(grep -F -c -- "${expected}" "${file}" || true)"
  [[ "${actual_count}" == "${expected_count}" ]] \
    || die "$(basename "${file}") expected ${expected_count} occurrences of ${expected}, found ${actual_count}"
}

for command in helm grep mktemp; do
  require_command "${command}"
done

[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
[[ -f "${secure_values}" ]] || die "secure profile values are unavailable: ${secure_values}"
[[ -f "${admin_values}" ]] || die "Admin values are unavailable: ${admin_values}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-network-policy.XXXXXX")"

helm lint --strict "${chart_dir}" >"${work_dir}/lint-default.log"
helm lint --strict "${chart_dir}" -f "${secure_values}" >"${work_dir}/lint-secure.log"

render defaults
assert_not_contains "${work_dir}/defaults.yaml" "kind: NetworkPolicy"
assert_not_contains "${work_dir}/defaults.yaml" "kind: CiliumNetworkPolicy"

render secure_profile -f "${secure_values}"
assert_count "${work_dir}/secure_profile.yaml" "kind: NetworkPolicy" 3
assert_not_contains "${work_dir}/secure_profile.yaml" "kind: CiliumNetworkPolicy"
assert_contains "${work_dir}/secure_profile.yaml" "name: oxibelt-public-ingress"
assert_contains "${work_dir}/secure_profile.yaml" "name: oxibelt-metrics-ingress"
assert_contains "${work_dir}/secure_profile.yaml" "name: oxibelt-egress"
assert_not_contains "${work_dir}/secure_profile.yaml" "name: oxibelt-admin-ingress"
assert_contains "${work_dir}/secure_profile.yaml" "- port: http"
assert_contains "${work_dir}/secure_profile.yaml" "- port: https"
assert_contains "${work_dir}/secure_profile.yaml" "- port: http3"
assert_contains "${work_dir}/secure_profile.yaml" "- port: metrics"
assert_contains "${work_dir}/secure_profile.yaml" "kubernetes.io/metadata.name: monitoring"
assert_contains "${work_dir}/secure_profile.yaml" "app.kubernetes.io/name: prometheus"
assert_contains "${work_dir}/secure_profile.yaml" "k8s-app: kube-dns"
assert_not_contains "${work_dir}/secure_profile.yaml" "endPort:"

for workload_kind in Deployment DaemonSet; do
  render "secure_${workload_kind}" -f "${secure_values}" \
    --set-string "workload.kind=${workload_kind}"
  assert_contains "${work_dir}/secure_${workload_kind}.yaml" "kind: ${workload_kind}"
  assert_contains "${work_dir}/secure_${workload_kind}.yaml" "name: oxibelt-public-ingress"
  assert_contains "${work_dir}/secure_${workload_kind}.yaml" "name: oxibelt-egress"
  assert_contains "${work_dir}/secure_${workload_kind}.yaml" "app.kubernetes.io/instance: oxibelt"
done

render explicit_admin -f "${admin_values}" \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.ingress.admin.from=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"management"}},"podSelector":{"matchLabels":{"app.kubernetes.io/name":"oxibelt-gateway-controller"}}}]'
assert_contains "${work_dir}/explicit_admin.yaml" "name: oxibelt-admin-ingress"
assert_contains "${work_dir}/explicit_admin.yaml" "kubernetes.io/metadata.name: management"
assert_contains "${work_dir}/explicit_admin.yaml" "app.kubernetes.io/name: oxibelt-gateway-controller"
assert_contains "${work_dir}/explicit_admin.yaml" "- port: admin"

render explicit_destination \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.egress.destinations=[{"name":"primary-upstream","category":"upstream","to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"application"}},"podSelector":{"matchLabels":{"app.kubernetes.io/name":"upstream"}}}],"ports":[{"port":8443,"protocol":"TCP","endPort":8450}]}]'
assert_contains "${work_dir}/explicit_destination.yaml" "kubernetes.io/metadata.name: application"
assert_contains "${work_dir}/explicit_destination.yaml" "port: 8443"
assert_contains "${work_dir}/explicit_destination.yaml" "endPort: 8450"

render cilium_fqdn \
  --set networkPolicy.enabled=true \
  --set networkPolicy.cilium.enabled=true \
  --set-json 'networkPolicy.cilium.fqdnDestinations=[{"name":"ocsp","category":"revocation","matchNames":["ocsp.example.com"],"ports":[{"port":80,"protocol":"TCP"}]}]'
assert_contains "${work_dir}/cilium_fqdn.yaml" "kind: CiliumNetworkPolicy"
assert_contains "${work_dir}/cilium_fqdn.yaml" "k8s:app.kubernetes.io/name: oxibelt"
assert_contains "${work_dir}/cilium_fqdn.yaml" "matchName: \"ocsp.example.com\""
assert_contains "${work_dir}/cilium_fqdn.yaml" "matchPattern: \"*\""

expect_failure allow_all_with_peer_schema \
  --set networkPolicy.enabled=true \
  --set networkPolicy.ingress.public.allowAll=true \
  --set-json 'networkPolicy.ingress.public.from=[{"ipBlock":{"cidr":"0.0.0.0/0"}}]'
expect_failure_contains allow_all_with_peer_helper \
  "networkPolicy.ingress.public.allowAll cannot be combined" \
  --skip-schema-validation \
  --set networkPolicy.enabled=true \
  --set networkPolicy.ingress.public.allowAll=true \
  --set-json 'networkPolicy.ingress.public.from=[{"ipBlock":{"cidr":"0.0.0.0/0"}}]'

expect_failure empty_metric_peer_schema \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.ingress.metrics.from=[{}]'
expect_failure_contains empty_metric_peer_helper \
  "networkPolicy.ingress.metrics.from[0] must declare" \
  --skip-schema-validation \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.ingress.metrics.from=[{}]'

expect_failure invalid_cilium_prerequisite_schema \
  --set networkPolicy.cilium.enabled=true
expect_failure_contains invalid_cilium_prerequisite_helper \
  "networkPolicy.cilium.enabled requires networkPolicy.enabled=true" \
  --skip-schema-validation \
  --set networkPolicy.cilium.enabled=true

expect_failure wildcard_cilium_name_schema \
  --set networkPolicy.enabled=true \
  --set networkPolicy.cilium.enabled=true \
  --set-json 'networkPolicy.cilium.fqdnDestinations=[{"name":"ocsp","category":"revocation","matchNames":["*.example.com"],"ports":[{"port":80,"protocol":"TCP"}]}]'
expect_failure_contains wildcard_cilium_name_helper \
  "must be a lower-case exact DNS name without wildcards" \
  --skip-schema-validation \
  --set networkPolicy.enabled=true \
  --set networkPolicy.cilium.enabled=true \
  --set-json 'networkPolicy.cilium.fqdnDestinations=[{"name":"ocsp","category":"revocation","matchNames":["*.example.com"],"ports":[{"port":80,"protocol":"TCP"}]}]'

expect_failure_contains reversed_port_range_helper \
  "endPort must be between port and 65535" \
  --skip-schema-validation \
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.egress.destinations=[{"name":"primary-upstream","category":"upstream","to":[{"ipBlock":{"cidr":"192.0.2.0/24"}}],"ports":[{"port":8443,"protocol":"TCP","endPort":8442}]}]'

expect_failure_contains missing_kubernetes_api_destination_helper \
  "requires a kubernetes-api egress destination" \
  --skip-schema-validation \
  --set networkPolicy.enabled=true \
  --set kubernetesDiscovery.rbac.create=true

echo "Helm NetworkPolicy check passed"
