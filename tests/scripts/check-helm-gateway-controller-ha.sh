#!/usr/bin/env bash
# Validate the Gateway controller HA rendering and fail-closed Lease RBAC
# without creating Kubernetes or Docker resources.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt-gateway-controller"
temp_root="${TMPDIR:-/tmp}"
work_dir=""

die() {
  echo "Gateway controller HA Helm check: $*" >&2
  exit 1
}

cleanup() {
  local status="$?"
  set +e
  case "${work_dir}" in
    "${temp_root%/}"/oxibelt-gateway-controller-ha.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected HA Helm work directory: ${work_dir}" >&2
      ;;
  esac
  exit "${status}"
}
trap cleanup EXIT

for command in helm grep mktemp; do
  command -v "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
done

[[ -f "${chart_dir}/Chart.yaml" ]] || die "controller chart is unavailable: ${chart_dir}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-gateway-controller-ha.XXXXXX")"

helm lint --strict "${chart_dir}" >"${work_dir}/lint.log"
helm template controller-ha "${chart_dir}" --namespace control >"${work_dir}/default.yaml"

assert_contains() {
  local expected="$1"
  grep -F -- "${expected}" "${work_dir}/default.yaml" >/dev/null \
    || die "default manifest is missing: ${expected}"
}

assert_not_contains() {
  local unexpected="$1"
  if grep -F -- "${unexpected}" "${work_dir}/default.yaml" >/dev/null; then
    die "default manifest unexpectedly contains: ${unexpected}"
  fi
}

for expected in \
  "kind: PodDisruptionBudget" \
  "minAvailable: 1" \
  "kind: Deployment" \
  "replicas: 2" \
  "type: RollingUpdate" \
  "maxUnavailable: 0" \
  "maxSurge: 1" \
  "preferredDuringSchedulingIgnoredDuringExecution:" \
  "fieldPath: metadata.name" \
  "fieldPath: metadata.uid" \
  "--leader-election-namespace=control" \
  "--leader-election-lease-name=oxibelt-gateway-controller" \
  "--leader-election-lease-duration-seconds=15" \
  "--leader-election-renew-deadline-seconds=10" \
  "--leader-election-retry-period-seconds=2" \
  "--l4-bind-address=0.0.0.0" \
  "--l4-connect-timeout-ms=3000" \
  "--l4-idle-timeout-ms=75000" \
  "--udp-max-flows=8192" \
  "--udp-new-flow-rate=200r/s" \
  "--udp-new-flow-burst=400" \
  "--udp-datagram-rate=200r/s" \
  "--udp-datagram-burst=400" \
  "--udp-batch=auto" \
  "--udp-batch-size=16" \
  "apiVersion: coordination.k8s.io/v1" \
  "kind: Lease" \
  "resources: [\"leases\"]" \
  "verbs: [\"get\", \"watch\", \"patch\"]"; do
  assert_contains "${expected}"
done
assert_not_contains "type: Recreate"
assert_not_contains "verbs: [\"get\", \"watch\", \"patch\", \"create\"]"

lease_document="${work_dir}/lease.yaml"
helm template controller-ha "${chart_dir}" --namespace control \
  --show-only templates/lease.yaml >"${lease_document}"
grep -F -- "kind: Lease" "${lease_document}" >/dev/null || die "Lease template did not render"
if grep -Eq '^spec:' "${lease_document}"; then
  die "Helm-owned Lease must omit spec so upgrades cannot reset live leadership"
fi

role_document="${work_dir}/rbac.yaml"
helm template controller-ha "${chart_dir}" --namespace control \
  --show-only templates/rbac.yaml >"${role_document}"
grep -F -- 'name: oxibelt-gateway-controller-leader-election' "${role_document}" >/dev/null \
  || die "named leader-election Role did not render"
grep -F -- '- "oxibelt-gateway-controller"' "${role_document}" >/dev/null \
  || die "leader-election Role does not bind the exact selected Lease name"
for expected in \
  '"tcproutes", "udproutes", "backendtlspolicies"' \
  '"tcproutes/status", "udproutes/status", "backendtlspolicies/status"' \
  'resources: ["configmaps"]' \
  'verbs: ["get"]'; do
  grep -F -- "${expected}" "${role_document}" >/dev/null \
    || die "Gateway API watch RBAC is missing: ${expected}"
done
if grep -F -- 'resources: ["secrets"]' "${role_document}" >/dev/null; then
  die "Gateway API watch RBAC must not grant Secret access"
fi
if grep -F -- 'verbs: ["get", "list"]' "${role_document}" >/dev/null; then
  die "Gateway API CA reads must not grant ConfigMap list"
fi

status_document="${work_dir}/status-addresses.yaml"
helm template controller-ha "${chart_dir}" --namespace control \
  --set-json 'statusAddresses=["203.0.113.10","gateway.example.test"]' \
  --show-only templates/deployment.yaml >"${status_document}"
grep -F -- '--status-address=203.0.113.10' "${status_document}" >/dev/null \
  || die "explicit IP status address did not render"
grep -F -- '--status-address=gateway.example.test' "${status_document}" >/dev/null \
  || die "explicit hostname status address did not render"

expect_failure() {
  local name="$1"
  local expected="$2"
  shift 2
  if helm template controller-ha "${chart_dir}" --namespace control --skip-schema-validation "$@" \
    >"${work_dir}/${name}.log" 2>&1; then
    die "${name} unexpectedly rendered successfully"
  fi
  grep -F -- "${expected}" "${work_dir}/${name}.log" >/dev/null \
    || die "${name} did not report the expected validation error: ${expected}"
}

expect_failure unsafe_timing \
  "leaderElection timings must satisfy" \
  --set leaderElection.leaseDurationSeconds=15 \
  --set leaderElection.renewDeadlineSeconds=14 \
  --set leaderElection.retryPeriodSeconds=2
expect_failure raw_anti_affinity_conflict \
  "podAntiAffinity.enabled=true cannot be combined with affinity.podAntiAffinity" \
  --set-json 'affinity.podAntiAffinity={}'

helm template controller-single "${chart_dir}" --namespace control \
  --set replicaCount=1 \
  --set podDisruptionBudget.enabled=false >"${work_dir}/single.yaml"
grep -F -- "replicas: 1" "${work_dir}/single.yaml" >/dev/null \
  || die "intentional single-replica override did not render"
if grep -F -- "kind: PodDisruptionBudget" "${work_dir}/single.yaml" >/dev/null; then
  die "disabled PodDisruptionBudget unexpectedly rendered"
fi

echo "Gateway controller HA Helm checks passed."
