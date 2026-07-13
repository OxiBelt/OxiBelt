#!/usr/bin/env bash
# Validate OxiBelt's CPU-plus-active-request HPA renderer contract without
# creating Kubernetes resources or handling Secret material.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
secure_values="${chart_dir}/examples/edge-secure-medium-v1-values.yaml"
autoscaling_values="${chart_dir}/examples/edge-secure-medium-v1-autoscaling-values.yaml"
temp_root="${TMPDIR:-/tmp}"
work_dir=""

die() {
  echo "Helm autoscaling check: $*" >&2
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
    "${temp_root%/}"/oxibelt-helm-autoscaling.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Helm autoscaling work directory: ${work_dir}" >&2
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

source_for() {
  local file="$1"
  local source="$2"

  awk -v source="# Source: oxibelt/${source}" '
    $0 == source { selected = 1 }
    selected { print }
    selected && /^---$/ { exit }
  ' "${file}"
}

assert_source_contains() {
  local file="$1"
  local source="$2"
  local expected="$3"
  local resource

  resource="$(source_for "${file}" "${source}")"
  grep -F -- "${expected}" <<<"${resource}" >/dev/null \
    || die "$(basename "${file}") ${source} is missing: ${expected}"
}

assert_source_not_contains() {
  local file="$1"
  local source="$2"
  local unexpected="$3"
  local resource

  resource="$(source_for "${file}" "${source}")"
  if grep -F -- "${unexpected}" <<<"${resource}" >/dev/null; then
    die "$(basename "${file}") ${source} unexpectedly contains: ${unexpected}"
  fi
}

for command in awk grep helm mktemp; do
  require_command "${command}"
done

[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
[[ -f "${secure_values}" ]] || die "secure profile values are unavailable: ${secure_values}"
[[ -f "${autoscaling_values}" ]] || die "autoscaling values are unavailable: ${autoscaling_values}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-autoscaling.XXXXXX")"

helm lint --strict "${chart_dir}" >"${work_dir}/lint-default.log"
helm lint --strict "${chart_dir}" --kube-version 1.31.4 \
  -f "${secure_values}" \
  -f "${autoscaling_values}" >"${work_dir}/lint-autoscaling.log"

render defaults
assert_not_contains "${work_dir}/defaults.yaml" "kind: HorizontalPodAutoscaler"

render cpu_only --set autoscaling.enabled=true
assert_source_contains "${work_dir}/cpu_only.yaml" "templates/hpa.yaml" "kind: HorizontalPodAutoscaler"
assert_source_contains "${work_dir}/cpu_only.yaml" "templates/hpa.yaml" "averageUtilization: 70"
assert_source_not_contains "${work_dir}/cpu_only.yaml" "templates/hpa.yaml" "oxibelt_active_http_requests"
assert_source_not_contains "${work_dir}/cpu_only.yaml" "templates/hpa.yaml" "behavior:"

render edge_secure_active_requests \
  --kube-version 1.31.4 \
  -f "${secure_values}" \
  -f "${autoscaling_values}"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "minReplicas: 3"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "maxReplicas: 10"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "averageUtilization: 70"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "type: Pods"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "name: oxibelt_active_http_requests"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "type: AverageValue"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "averageValue: 24"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "stabilizationWindowSeconds: 300"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "selectPolicy: Min"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "value: 1"
assert_source_contains "${work_dir}/edge_secure_active_requests.yaml" "templates/hpa.yaml" "periodSeconds: 360"

expect_failure_contains daemonset_hpa \
  "autoscaling.enabled=true requires workload.kind=Deployment" \
  --set autoscaling.enabled=true \
  --set workload.kind=DaemonSet
expect_failure_contains replica_bounds \
  "autoscaling.maxReplicas must be at least autoscaling.minReplicas" \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=4 \
  --set autoscaling.maxReplicas=3
expect_failure_contains active_requests_requires_hpa \
  "autoscaling.activeRequests.enabled=true requires autoscaling.enabled=true" \
  --set autoscaling.activeRequests.enabled=true
expect_failure_contains active_requests_without_profile \
  "autoscaling.activeRequests.enabled=true requires operationalProfile.name=edge-secure-medium so the active-work gauge is sampled" \
  --set autoscaling.enabled=true \
  --set autoscaling.activeRequests.enabled=true \
  --set lifecycle.preStop.enabled=true \
  --set lifecycle.terminationGracePeriodSeconds=300
expect_failure_contains metrics_disabled \
  "autoscaling.activeRequests.enabled=true requires metrics.enabled=true" \
  -f "${secure_values}" \
  -f "${autoscaling_values}" \
  --set metrics.enabled=false
expect_failure_contains prestop_disabled \
  "autoscaling.activeRequests.enabled=true requires lifecycle.preStop.enabled=true" \
  -f "${secure_values}" \
  -f "${autoscaling_values}" \
  --set lifecycle.preStop.enabled=false
expect_failure_contains zero_grace \
  "autoscaling.activeRequests.enabled=true requires lifecycle.terminationGracePeriodSeconds greater than zero" \
  -f "${secure_values}" \
  -f "${autoscaling_values}" \
  --set lifecycle.terminationGracePeriodSeconds=0
expect_failure_contains short_stabilization \
  "autoscaling.scaleDown.stabilizationWindowSeconds must be at least lifecycle.preStop.drainSeconds when autoscaling.activeRequests.enabled=true" \
  -f "${secure_values}" \
  -f "${autoscaling_values}" \
  --set autoscaling.scaleDown.stabilizationWindowSeconds=299
expect_failure_contains short_period \
  "autoscaling.scaleDown.periodSeconds must be at least lifecycle.terminationGracePeriodSeconds when autoscaling.activeRequests.enabled=true" \
  -f "${secure_values}" \
  -f "${autoscaling_values}" \
  --set autoscaling.scaleDown.periodSeconds=359
expect_failure invalid_stabilization_range \
  -f "${secure_values}" \
  -f "${autoscaling_values}" \
  --set autoscaling.scaleDown.stabilizationWindowSeconds=3601
expect_failure invalid_period_range \
  -f "${secure_values}" \
  -f "${autoscaling_values}" \
  --set autoscaling.scaleDown.periodSeconds=1801
expect_failure invalid_target_type \
  -f "${secure_values}" \
  -f "${autoscaling_values}" \
  --set-string autoscaling.activeRequests.targetAverageValue=24Gi
expect_failure unknown_active_request_setting \
  -f "${secure_values}" \
  -f "${autoscaling_values}" \
  --set autoscaling.activeRequests.unexpected=true

echo "Helm autoscaling check passed."
