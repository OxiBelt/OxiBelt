#!/usr/bin/env bash
# Validate OxiBelt's Pod distribution, disruption-budget, and pre-stop drain
# renderer contract without creating Kubernetes resources or handling Secret
# material.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
secure_values="${chart_dir}/examples/edge-secure-medium-v1-values.yaml"
temp_root="${TMPDIR:-/tmp}"
work_dir=""

die() {
  echo "Helm Pod lifecycle check: $*" >&2
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
    "${temp_root%/}"/oxibelt-helm-pod-lifecycle.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Helm Pod lifecycle work directory: ${work_dir}" >&2
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

assert_occurrence_count() {
  local file="$1"
  local expected="$2"
  local expected_count="$3"
  local actual_count

  actual_count="$(grep -F -c -- "${expected}" "${file}" || true)"
  [[ "${actual_count}" == "${expected_count}" ]] \
    || die "$(basename "${file}") expected ${expected_count} occurrences of ${expected}, found ${actual_count}"
}

assert_source_contains() {
  local file="$1"
  local source="$2"
  local expected="$3"
  local resource

  resource="$(awk -v source="# Source: oxibelt/${source}" '
    $0 == source { selected = 1 }
    selected { print }
    selected && /^---$/ { exit }
  ' "${file}")"
  grep -F -- "${expected}" <<<"${resource}" >/dev/null \
    || die "$(basename "${file}") ${source} is missing: ${expected}"
}

assert_source_not_contains() {
  local file="$1"
  local source="$2"
  local unexpected="$3"
  local resource

  resource="$(awk -v source="# Source: oxibelt/${source}" '
    $0 == source { selected = 1 }
    selected { print }
    selected && /^---$/ { exit }
  ' "${file}")"
  if grep -F -- "${unexpected}" <<<"${resource}" >/dev/null; then
    die "$(basename "${file}") ${source} unexpectedly contains: ${unexpected}"
  fi
}

for command in awk grep helm mktemp; do
  require_command "${command}"
done

[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
[[ -f "${secure_values}" ]] || die "secure profile values are unavailable: ${secure_values}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-pod-lifecycle.XXXXXX")"

helm lint --strict "${chart_dir}" >"${work_dir}/lint-default.log"
helm lint --strict "${chart_dir}" --kube-version 1.31.14 -f "${secure_values}" >"${work_dir}/lint-secure.log"

render defaults
assert_not_contains "${work_dir}/defaults.yaml" "topologySpreadConstraints:"
assert_not_contains "${work_dir}/defaults.yaml" "podAntiAffinity:"
assert_not_contains "${work_dir}/defaults.yaml" "preStop:"
assert_not_contains "${work_dir}/defaults.yaml" "terminationGracePeriodSeconds:"
assert_source_contains "${work_dir}/defaults.yaml" "templates/pdb.yaml" "minAvailable: 1"
assert_source_not_contains "${work_dir}/defaults.yaml" "templates/pdb.yaml" "maxUnavailable:"

render distributed \
  --kube-version 1.31.14 \
  --set replicaCount=3 \
  --set podDistribution.enabled=true \
  --set lifecycle.preStop.enabled=true \
  --set lifecycle.preStop.drainSeconds=10 \
  --set lifecycle.terminationGracePeriodSeconds=45 \
  --set-json podDisruptionBudget.minAvailable=null \
  --set podDisruptionBudget.maxUnavailable=1 \
  --set-string podDisruptionBudget.unhealthyPodEvictionPolicy=AlwaysAllow
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "topologySpreadConstraints:"
assert_occurrence_count "${work_dir}/distributed.yaml" "nodeTaintsPolicy: Honor" 2
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "topologyKey: kubernetes.io/hostname"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "minDomains: 2"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "whenUnsatisfiable: DoNotSchedule"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "topologyKey: topology.kubernetes.io/zone"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "whenUnsatisfiable: ScheduleAnyway"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "podAntiAffinity:"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "preferredDuringSchedulingIgnoredDuringExecution:"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "weight: 100"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "preStop:"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "- /bin/sh"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "- -ec"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "kill -USR1 1; exec sleep 10"
assert_source_contains "${work_dir}/distributed.yaml" "templates/deployment.yaml" "terminationGracePeriodSeconds: 45"
assert_source_contains "${work_dir}/distributed.yaml" "templates/pdb.yaml" "maxUnavailable: 1"
assert_source_not_contains "${work_dir}/distributed.yaml" "templates/pdb.yaml" "minAvailable:"
assert_source_contains "${work_dir}/distributed.yaml" "templates/pdb.yaml" "unhealthyPodEvictionPolicy: AlwaysAllow"

render secure_profile --kube-version 1.31.14 -f "${secure_values}"
assert_source_contains "${work_dir}/secure_profile.yaml" "templates/deployment.yaml" "replicas: 3"
assert_source_contains "${work_dir}/secure_profile.yaml" "templates/deployment.yaml" "topologySpreadConstraints:"
assert_occurrence_count "${work_dir}/secure_profile.yaml" "nodeTaintsPolicy: Honor" 2
assert_source_contains "${work_dir}/secure_profile.yaml" "templates/deployment.yaml" "topologyKey: kubernetes.io/hostname"
assert_source_contains "${work_dir}/secure_profile.yaml" "templates/deployment.yaml" "topologyKey: topology.kubernetes.io/zone"
assert_source_contains "${work_dir}/secure_profile.yaml" "templates/deployment.yaml" "podAntiAffinity:"
assert_source_contains "${work_dir}/secure_profile.yaml" "templates/deployment.yaml" "kill -USR1 1; exec sleep 300"
assert_source_contains "${work_dir}/secure_profile.yaml" "templates/deployment.yaml" "terminationGracePeriodSeconds: 360"
assert_source_contains "${work_dir}/secure_profile.yaml" "templates/pdb.yaml" "maxUnavailable: 1"
assert_source_contains "${work_dir}/secure_profile.yaml" "templates/pdb.yaml" "unhealthyPodEvictionPolicy: AlwaysAllow"

render secure_daemonset --kube-version 1.31.14 -f "${secure_values}" \
  --set-string workload.kind=DaemonSet
assert_source_contains "${work_dir}/secure_daemonset.yaml" "templates/daemonset.yaml" "kind: DaemonSet"
assert_source_contains "${work_dir}/secure_daemonset.yaml" "templates/daemonset.yaml" "maxUnavailable: 0"
assert_source_contains "${work_dir}/secure_daemonset.yaml" "templates/daemonset.yaml" "maxSurge: 1"
assert_source_contains "${work_dir}/secure_daemonset.yaml" "templates/daemonset.yaml" "kill -USR1 1; exec sleep 300"
assert_source_not_contains "${work_dir}/secure_daemonset.yaml" "templates/daemonset.yaml" "topologySpreadConstraints:"
assert_source_not_contains "${work_dir}/secure_daemonset.yaml" "templates/daemonset.yaml" "podAntiAffinity:"
assert_not_contains "${work_dir}/secure_daemonset.yaml" "# Source: oxibelt/templates/pdb.yaml"

expect_failure_contains distributed_requires_kubernetes_130 \
  "podDistribution.nodeSpread.minDomains requires Kubernetes 1.30 or later" \
  --kube-version 1.29.0 \
  --set podDistribution.enabled=true

expect_failure_contains node_spread_min_domains_requires_do_not_schedule \
  "podDistribution.nodeSpread.minDomains requires podDistribution.nodeSpread.whenUnsatisfiable=DoNotSchedule" \
  --kube-version 1.31.0 \
  --set podDistribution.enabled=true \
  --set-string podDistribution.nodeSpread.whenUnsatisfiable=ScheduleAnyway

expect_failure_contains secure_profile_requires_kubernetes_131 \
  "operationalProfile edge-secure-medium requires Kubernetes 1.31 or later" \
  --kube-version 1.30.0 \
  -f "${secure_values}"

expect_failure_contains secure_profile_requires_deployment_zero_unavailable \
  "operationalProfile edge-secure-medium requires Deployment maxUnavailable=0 and maxSurge=1" \
  --kube-version 1.31.14 \
  -f "${secure_values}" \
  --set workload.deployment.maxUnavailable=1

expect_failure_contains secure_profile_requires_deployment_one_surge \
  "operationalProfile edge-secure-medium requires Deployment maxUnavailable=0 and maxSurge=1" \
  --kube-version 1.31.14 \
  -f "${secure_values}" \
  --set workload.deployment.maxSurge=2

expect_failure_contains secure_profile_requires_valid_hpa_bounds \
  "operationalProfile edge-secure-medium requires autoscaling.maxReplicas to be at least autoscaling.minReplicas" \
  --kube-version 1.31.14 \
  -f "${secure_values}" \
  --set autoscaling.enabled=true \
  --set autoscaling.maxReplicas=2

expect_failure managed_anti_affinity_conflict \
  --skip-schema-validation \
  --set podDistribution.enabled=true \
  --set-json 'affinity.podAntiAffinity={"requiredDuringSchedulingIgnoredDuringExecution":[]}'

expect_failure pre_stop_requires_positive_drain \
  --skip-schema-validation \
  --set lifecycle.preStop.enabled=true \
  --set lifecycle.preStop.drainSeconds=0

expect_failure pre_stop_rejects_shell_injection \
  --skip-schema-validation \
  --set lifecycle.preStop.enabled=true \
  --set-string 'lifecycle.preStop.drainSeconds=10;touch /tmp/unsafe'

huge_decimal=999999999999999999999
expect_failure_contains termination_grace_rejects_int_overflow \
  "lifecycle.terminationGracePeriodSeconds must be a non-negative integer no greater than 999999999" \
  --skip-schema-validation \
  --set-string "lifecycle.terminationGracePeriodSeconds=${huge_decimal}"

expect_failure_contains topology_spread_rejects_int_overflow \
  "podDistribution.nodeSpread.maxSkew must be a positive integer no greater than 999999999" \
  --skip-schema-validation \
  --set podDistribution.enabled=true \
  --set-string "podDistribution.nodeSpread.maxSkew=${huge_decimal}"

expect_failure_contains anti_affinity_rejects_int_overflow \
  "podDistribution.podAntiAffinity.weight must be an integer between 1 and 100" \
  --skip-schema-validation \
  --set podDistribution.enabled=true \
  --set-string "podDistribution.podAntiAffinity.weight=${huge_decimal}"

expect_failure_contains pdb_rejects_int_overflow \
  "podDisruptionBudget.maxUnavailable must be a non-negative integer no greater than 999999999 or percentage" \
  --skip-schema-validation \
  --set-json podDisruptionBudget.minAvailable=null \
  --set-string "podDisruptionBudget.maxUnavailable=${huge_decimal}"

expect_failure_contains daemonset_rollout_rejects_int_overflow \
  "workload.daemonSet.maxUnavailable must be a non-negative integer no greater than 999999999" \
  --skip-schema-validation \
  --set-string workload.kind=DaemonSet \
  --set-string "workload.daemonSet.maxUnavailable=${huge_decimal}"

expect_failure pdb_rejects_both_availability_forms \
  --skip-schema-validation \
  --set podDisruptionBudget.minAvailable=1 \
  --set podDisruptionBudget.maxUnavailable=1

expect_failure pdb_requires_an_availability_form \
  --skip-schema-validation \
  --set-json podDisruptionBudget.minAvailable=null \
  --set-json podDisruptionBudget.maxUnavailable=null

expect_failure daemonset_requires_progress \
  --skip-schema-validation \
  --set-string workload.kind=DaemonSet \
  --set workload.daemonSet.maxUnavailable=0 \
  --set workload.daemonSet.maxSurge=0

echo "Helm Pod lifecycle check passed"
