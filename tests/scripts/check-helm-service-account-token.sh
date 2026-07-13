#!/usr/bin/env bash
# Validate ServiceAccount token hardening and least-privilege Kubernetes RBAC
# without creating Kubernetes resources or reading credential material.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
data_chart_dir="${repo_root}/deploy/helm/oxibelt"
controller_chart_dir="${repo_root}/deploy/helm/oxibelt-gateway-controller"
temp_root="${TMPDIR:-/tmp}"
work_dir=""

die() {
  echo "Helm ServiceAccount token check: $*" >&2
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
    "${temp_root%/}"/oxibelt-helm-service-account-token.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Helm ServiceAccount token work directory: ${work_dir}" >&2
      ;;
  esac

  exit "${status}"
}
trap cleanup EXIT

render_data() {
  local name="$1"
  shift
  helm template token-check "${data_chart_dir}" "$@" >"${work_dir}/data-${name}.yaml"
}

render_controller() {
  local name="$1"
  shift
  helm template controller-check "${controller_chart_dir}" "$@" >"${work_dir}/controller-${name}.yaml"
}

expect_data_failure() {
  local name="$1"
  shift

  if helm template token-check "${data_chart_dir}" "$@" >"${work_dir}/data-${name}.log" 2>&1; then
    die "data-plane ${name} unexpectedly rendered successfully"
  fi
}

expect_data_failure_contains() {
  local name="$1"
  local expected="$2"
  shift 2

  expect_data_failure "${name}" "$@"
  grep -F -- "${expected}" "${work_dir}/data-${name}.log" >/dev/null \
    || die "data-plane ${name} did not report the expected validation failure: ${expected}"
}

expect_controller_failure() {
  local name="$1"
  shift

  if helm template controller-check "${controller_chart_dir}" "$@" >"${work_dir}/controller-${name}.log" 2>&1; then
    die "controller ${name} unexpectedly rendered successfully"
  fi
}

expect_controller_failure_contains() {
  local name="$1"
  local expected="$2"
  shift 2

  expect_controller_failure "${name}" "$@"
  grep -F -- "${expected}" "${work_dir}/controller-${name}.log" >/dev/null \
    || die "controller ${name} did not report the expected validation failure: ${expected}"
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

assert_exact_line_count() {
  local file="$1"
  local expected="$2"
  local expected_count="$3"
  local actual_count

  actual_count="$(grep -Fxc -- "${expected}" "${file}" || true)"
  [[ "${actual_count}" == "${expected_count}" ]] \
    || die "$(basename "${file}") expected ${expected_count} lines equal to ${expected}, found ${actual_count}"
}

assert_occurrence_count() {
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

[[ -f "${data_chart_dir}/Chart.yaml" ]] || die "data-plane chart is unavailable: ${data_chart_dir}"
[[ -f "${controller_chart_dir}/Chart.yaml" ]] \
  || die "controller chart is unavailable: ${controller_chart_dir}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-service-account-token.XXXXXX")"

helm lint --strict "${data_chart_dir}" >"${work_dir}/data-lint.log"
helm lint --strict "${controller_chart_dir}" >"${work_dir}/controller-lint.log"

# The data plane must have no Kubernetes API credential or discovery RBAC by
# default, regardless of whether it creates its ServiceAccount itself.
render_data default
assert_occurrence_count "${work_dir}/data-default.yaml" "automountServiceAccountToken: false" 2
assert_not_contains "${work_dir}/data-default.yaml" "name: kube-api-access"
assert_not_contains "${work_dir}/data-default.yaml" "serviceAccountToken:"
assert_not_contains "${work_dir}/data-default.yaml" "# Source: oxibelt/templates/rbac.yaml"

render_data daemonset_default --set-string workload.kind=DaemonSet
assert_contains "${work_dir}/data-daemonset_default.yaml" "kind: DaemonSet"
assert_occurrence_count "${work_dir}/data-daemonset_default.yaml" "automountServiceAccountToken: false" 2
assert_not_contains "${work_dir}/data-daemonset_default.yaml" "name: kube-api-access"

render_data external_service_account \
  --set serviceAccount.create=false \
  --set-string serviceAccount.name=operator-managed
assert_occurrence_count "${work_dir}/data-external_service_account.yaml" "automountServiceAccountToken: false" 1
assert_contains "${work_dir}/data-external_service_account.yaml" "serviceAccountName: operator-managed"
assert_not_contains "${work_dir}/data-external_service_account.yaml" "name: kube-api-access"

# Chart-created discovery RBAC is namespace-scoped and creates the one explicit
# API credential projection necessary for an operator-configured discovery path.
render_data discovery_rbac \
  --show-only templates/rbac.yaml \
  --set kubernetesDiscovery.rbac.create=true \
  --set-json 'kubernetesDiscovery.rbac.namespaces=["edge-a","edge-b"]'
assert_exact_line_count "${work_dir}/data-discovery_rbac.yaml" "kind: Role" 2
assert_exact_line_count "${work_dir}/data-discovery_rbac.yaml" "kind: RoleBinding" 2
assert_contains "${work_dir}/data-discovery_rbac.yaml" "namespace: \"edge-a\""
assert_contains "${work_dir}/data-discovery_rbac.yaml" "namespace: \"edge-b\""
assert_contains "${work_dir}/data-discovery_rbac.yaml" "resources: [\"endpointslices\"]"
assert_contains "${work_dir}/data-discovery_rbac.yaml" "verbs: [\"list\", \"watch\"]"
assert_contains "${work_dir}/data-discovery_rbac.yaml" "resources: [\"endpoints\"]"
assert_contains "${work_dir}/data-discovery_rbac.yaml" "verbs: [\"get\"]"
assert_not_contains "${work_dir}/data-discovery_rbac.yaml" "kind: ClusterRole"
assert_not_contains "${work_dir}/data-discovery_rbac.yaml" "kind: ClusterRoleBinding"
assert_not_contains "${work_dir}/data-discovery_rbac.yaml" "resources: [\"services\"]"
assert_not_contains "${work_dir}/data-discovery_rbac.yaml" "verbs: [\"get\", \"list\", \"watch\"]"

render_data discovery_projection --show-only templates/deployment.yaml \
  --set kubernetesDiscovery.rbac.create=true
assert_contains "${work_dir}/data-discovery_projection.yaml" "automountServiceAccountToken: false"
assert_contains "${work_dir}/data-discovery_projection.yaml" "name: kube-api-access"
assert_contains "${work_dir}/data-discovery_projection.yaml" "mountPath: /var/run/secrets/kubernetes.io/serviceaccount"
assert_contains "${work_dir}/data-discovery_projection.yaml" "serviceAccountToken:"
assert_contains "${work_dir}/data-discovery_projection.yaml" "expirationSeconds: 3600"
assert_contains "${work_dir}/data-discovery_projection.yaml" "name: kube-root-ca.crt"
assert_contains "${work_dir}/data-discovery_projection.yaml" "defaultMode: 288"

# External RBAC may opt in to the same projection without causing this chart to
# grant any API permissions of its own.
render_data external_rbac_projection \
  --set kubernetesDiscovery.serviceAccountToken.enabled=true
assert_contains "${work_dir}/data-external_rbac_projection.yaml" "name: kube-api-access"
assert_not_contains "${work_dir}/data-external_rbac_projection.yaml" "# Source: oxibelt/templates/rbac.yaml"

expect_data_failure service_account_automount_schema \
  --set serviceAccount.automountServiceAccountToken=true
expect_data_failure_contains service_account_automount_helper \
  "serviceAccount.automountServiceAccountToken must remain false" \
  --skip-schema-validation \
  --set serviceAccount.automountServiceAccountToken=true
expect_data_failure discovery_expiration_schema \
  --set kubernetesDiscovery.serviceAccountToken.expirationSeconds=599
expect_data_failure_contains discovery_expiration_helper \
  "kubernetesDiscovery.serviceAccountToken.expirationSeconds must be between 600 and 3600" \
  --skip-schema-validation \
  --set kubernetesDiscovery.serviceAccountToken.expirationSeconds=599
expect_data_failure discovery_duplicate_namespace_schema \
  --set-json 'kubernetesDiscovery.rbac.namespaces=["edge-a","edge-a"]'
expect_data_failure_contains discovery_duplicate_namespace_helper \
  "kubernetesDiscovery.rbac.namespaces must not contain duplicates" \
  --skip-schema-validation \
  --set-json 'kubernetesDiscovery.rbac.namespaces=["edge-a","edge-a"]'
expect_data_failure_contains discovery_oversized_namespace_helper \
  "kubernetesDiscovery.rbac.namespaces must contain safe Kubernetes namespace names" \
  --skip-schema-validation \
  --set-json 'kubernetesDiscovery.rbac.namespaces=["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]'

# The controller always needs the Kubernetes API, but it receives a bounded
# explicit projection and scopes its Gateway reads to its release namespace by
# default.
render_controller default
assert_occurrence_count "${work_dir}/controller-default.yaml" "automountServiceAccountToken: false" 2
assert_contains "${work_dir}/controller-default.yaml" "--watch-namespace=default"
assert_contains "${work_dir}/controller-default.yaml" "name: kube-api-access"
assert_contains "${work_dir}/controller-default.yaml" "mountPath: /var/run/secrets/kubernetes.io/serviceaccount"
assert_contains "${work_dir}/controller-default.yaml" "serviceAccountToken:"
assert_contains "${work_dir}/controller-default.yaml" "expirationSeconds: 3600"
assert_contains "${work_dir}/controller-default.yaml" "name: kube-root-ca.crt"
assert_contains "${work_dir}/controller-default.yaml" "defaultMode: 288"
assert_contains "${work_dir}/controller-default.yaml" "resourceNames:"
assert_contains "${work_dir}/controller-default.yaml" "verbs: [\"get\"]"
assert_contains "${work_dir}/controller-default.yaml" "verbs: [\"list\"]"
assert_contains "${work_dir}/controller-default.yaml" "verbs: [\"patch\"]"
assert_not_contains "${work_dir}/controller-default.yaml" "verbs: [\"get\", \"list\", \"watch\"]"
assert_not_contains "${work_dir}/controller-default.yaml" "verbs: [\"get\", \"patch\", \"update\"]"
assert_not_contains "${work_dir}/controller-default.yaml" "resources: [\"secrets\"]"
assert_not_contains "${work_dir}/controller-default.yaml" "verbs: [\"delete\"]"

render_controller scoped_watch --set-string watchNamespace=edge-a
assert_contains "${work_dir}/controller-scoped_watch.yaml" "--watch-namespace=edge-a"
assert_contains "${work_dir}/controller-scoped_watch.yaml" "namespace: \"edge-a\""
assert_contains "${work_dir}/controller-scoped_watch.yaml" "- \"edge-a\""

render_controller clusterwide_watch --set watchAllNamespaces=true
assert_not_contains "${work_dir}/controller-clusterwide_watch.yaml" "--watch-namespace="
assert_contains "${work_dir}/controller-clusterwide_watch.yaml" "name: oxibelt-gateway-controller-watch"
assert_contains "${work_dir}/controller-clusterwide_watch.yaml" "resources: [\"namespaces\"]"
assert_contains "${work_dir}/controller-clusterwide_watch.yaml" "verbs: [\"list\"]"

expect_controller_failure service_account_automount_schema \
  --set serviceAccount.automountServiceAccountToken=true
expect_controller_failure_contains service_account_automount_helper \
  "serviceAccount.automountServiceAccountToken must remain false" \
  --skip-schema-validation \
  --set serviceAccount.automountServiceAccountToken=true
expect_controller_failure token_expiration_schema \
  --set serviceAccount.tokenProjection.expirationSeconds=599
expect_controller_failure_contains token_expiration_helper \
  "serviceAccount.tokenProjection.expirationSeconds must be between 600 and 3600" \
  --skip-schema-validation \
  --set serviceAccount.tokenProjection.expirationSeconds=599
expect_controller_failure conflicting_scope_schema \
  --set watchAllNamespaces=true \
  --set-string watchNamespace=edge-a
expect_controller_failure_contains conflicting_scope_helper \
  "watchAllNamespaces=true cannot be combined with watchNamespace" \
  --skip-schema-validation \
  --set watchAllNamespaces=true \
  --set-string watchNamespace=edge-a
expect_controller_failure_contains oversized_watch_namespace_helper \
  "watchNamespace must be a safe Kubernetes namespace name" \
  --skip-schema-validation \
  --set-string watchNamespace=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

echo "Helm ServiceAccount token check passed"
