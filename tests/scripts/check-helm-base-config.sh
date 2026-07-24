#!/usr/bin/env bash
# Validate chart-owned and operator-managed base ConfigMap selection without
# creating Kubernetes resources.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
kubernetes_version="1.34.8"
temp_root="${TMPDIR:-/tmp}"
work_dir=""
empty_config_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
external_config_digest="1111111111111111111111111111111111111111111111111111111111111111"

die() {
  echo "Helm base configuration check: $*" >&2
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
    "${temp_root%/}"/oxibelt-helm-base-config.*)
      rm -rf "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Helm base configuration work directory: ${work_dir}" >&2
      ;;
  esac

  exit "${status}"
}
trap cleanup EXIT

render() {
  local name="$1"
  shift
  helm template oxibelt "${chart_dir}" --kube-version "${kubernetes_version}" \
    "$@" >"${work_dir}/${name}.yaml"
}

expect_failure() {
  local name="$1"
  shift

  if helm template oxibelt "${chart_dir}" --kube-version "${kubernetes_version}" \
    "$@" >"${work_dir}/${name}.log" 2>&1; then
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

for command in helm grep mktemp; do
  require_command "${command}"
done

[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-base-config.XXXXXX")"

helm lint --strict "${chart_dir}" --kube-version "${kubernetes_version}" >"${work_dir}/lint.log"

render chart_created_default
assert_contains "${work_dir}/chart_created_default.yaml" "kind: ConfigMap"
assert_contains "${work_dir}/chart_created_default.yaml" "immutable: true"
assert_contains "${work_dir}/chart_created_default.yaml" "oxibelt.dev/effective-version: \"0.0.0\""
assert_contains "${work_dir}/chart_created_default.yaml" "oxibelt.dev/feature-status: \"experimental\""
assert_contains "${work_dir}/chart_created_default.yaml" "oxibelt.dev/kubernetes-support-policy: \"1\""
assert_not_contains "${work_dir}/chart_created_default.yaml" "oxibelt.dev/immutable-config-rollout: \"true\""

render explicit_effective_version --set-string effectiveVersion=0.7.0-dev.abc12345
assert_contains "${work_dir}/explicit_effective_version.yaml" \
  "oxibelt.dev/effective-version: \"0.7.0-dev.abc12345\""
assert_contains "${work_dir}/explicit_effective_version.yaml" \
  "app.kubernetes.io/version: \"0.7.0-dev.abc12345\""

for workload_kind in Deployment DaemonSet; do
  render "chart_created_${workload_kind}" \
    --set-string "workload.kind=${workload_kind}" \
    --set-string "configRollout.mode=kubernetes_immutable"
  assert_contains "${work_dir}/chart_created_${workload_kind}.yaml" "kind: ${workload_kind}"
  assert_contains "${work_dir}/chart_created_${workload_kind}.yaml" "oxibelt.dev/immutable-config-rollout: \"true\""
  assert_contains "${work_dir}/chart_created_${workload_kind}.yaml" "oxibelt.dev/config-revision: \"oxibelt-config-"
  assert_contains "${work_dir}/chart_created_${workload_kind}.yaml" "oxibelt.dev/config-digest: \"${empty_config_digest}\""

  for config_create in true false; do
    render "external_${workload_kind}_${config_create}" \
      --set-string "workload.kind=${workload_kind}" \
      --set-string "configRollout.mode=kubernetes_immutable" \
      --set "config.create=${config_create}" \
      --set-string "config.existingConfigMap=operator-managed-base" \
      --set-string "config.existingConfigMapDigest=${external_config_digest}"
    assert_contains "${work_dir}/external_${workload_kind}_${config_create}.yaml" "kind: ${workload_kind}"
    assert_contains "${work_dir}/external_${workload_kind}_${config_create}.yaml" "name: operator-managed-base"
    assert_contains "${work_dir}/external_${workload_kind}_${config_create}.yaml" "oxibelt.dev/immutable-config-rollout: \"true\""
    assert_not_contains "${work_dir}/external_${workload_kind}_${config_create}.yaml" "# Source: oxibelt/templates/configmap.yaml"
    assert_not_contains "${work_dir}/external_${workload_kind}_${config_create}.yaml" "oxibelt.dev/config-revision:"
    assert_not_contains "${work_dir}/external_${workload_kind}_${config_create}.yaml" "oxibelt.dev/config-digest:"
  done
done

for rollout_mode in helm_immutable kubernetes_immutable; do
  for workload_kind in Deployment DaemonSet; do
    case_name="uncreated_${rollout_mode}_${workload_kind}"
    expect_failure "${case_name}_schema" \
      --set-string "workload.kind=${workload_kind}" \
      --set-string "configRollout.mode=${rollout_mode}" \
      --set "config.create=false" \
      --set-string "config.existingConfigMap="
    expect_failure_contains "${case_name}_render" \
      "config.existingConfigMap is required when config.create=false" \
      --skip-schema-validation \
      --set-string "workload.kind=${workload_kind}" \
      --set-string "configRollout.mode=${rollout_mode}" \
      --set "config.create=false" \
      --set-string "config.existingConfigMap="
  done
done

if helm template oxibelt "${chart_dir}" --kube-version 1.33.0 \
  --set-string configRollout.mode=kubernetes_immutable \
  >"${work_dir}/unsupported-kubernetes.log" 2>&1; then
  die "kubernetes_immutable unexpectedly rendered for Kubernetes 1.33"
fi
assert_contains "${work_dir}/unsupported-kubernetes.log" \
  "configRollout.mode=kubernetes_immutable requires Kubernetes >=1.34.0 and <1.37.0"

helm template oxibelt "${chart_dir}" --kube-version 1.31.14 \
  --set-string configRollout.mode=helm_immutable \
  >"${work_dir}/legacy-helm-immutable.yaml"
assert_contains "${work_dir}/legacy-helm-immutable.yaml" "kind: Deployment"

echo "Helm base configuration check passed"
