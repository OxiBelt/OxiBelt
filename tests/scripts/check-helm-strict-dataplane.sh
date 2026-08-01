#!/usr/bin/env bash
# Validate the optional compile-time Admin-free Helm role without creating
# Kubernetes resources or reading Secret material.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
strict_values="${chart_dir}/examples/strict-dataplane-values.yaml"
secure_values="${chart_dir}/examples/edge-secure-medium-v1-values.yaml"
seccomp_validator="${repo_root}/tests/scripts/check-seccomp-profile-contract.py"
seccomp_validator_tests="${repo_root}/tests/scripts/test-check-seccomp-profile-contract.py"
temp_root="${TMPDIR:-/tmp}"
work_dir=""

die() {
  echo "Helm strict data-plane check: $*" >&2
  exit 1
}

cleanup() {
  local status="$?"
  set +e

  case "${work_dir}" in
    "${temp_root%/}"/oxibelt-helm-strict-dataplane.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Helm strict data-plane work directory: ${work_dir}" >&2
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
  local expected="$2"
  shift 2

  if helm template oxibelt "${chart_dir}" "$@" >"${work_dir}/${name}.log" 2>&1; then
    die "${name} unexpectedly rendered successfully"
  fi
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

for command in grep helm mktemp python3; do
  command -v "${command}" >/dev/null 2>&1 \
    || die "required command is unavailable: ${command}"
done

[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
[[ -f "${strict_values}" ]] || die "strict values example is unavailable: ${strict_values}"
[[ -f "${secure_values}" ]] || die "secure profile values are unavailable: ${secure_values}"
[[ -f "${seccomp_validator}" ]] || die "seccomp profile validator is unavailable: ${seccomp_validator}"
[[ -f "${seccomp_validator_tests}" ]] || die "seccomp profile validator tests are unavailable: ${seccomp_validator_tests}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-strict-dataplane.XXXXXX")"

python3 "${seccomp_validator}" >"${work_dir}/seccomp-profile-contract.log"
python3 "${seccomp_validator_tests}" >"${work_dir}/seccomp-profile-contract-tests.log" 2>&1
helm lint --strict "${chart_dir}" >"${work_dir}/lint-default.log"
helm lint --strict "${chart_dir}" -f "${strict_values}" >"${work_dir}/lint-strict.log"

render compatibility
assert_contains "${work_dir}/compatibility.yaml" 'image: "ghcr.io/oxibelt/oxibelt-dataplane:latest"'
assert_contains "${work_dir}/compatibility.yaml" 'command: ["/usr/local/bin/oxibelt"]'
assert_contains "${work_dir}/compatibility.yaml" '[admin]'
assert_contains "${work_dir}/compatibility.yaml" 'mountPath: /var/cache/oxibelt'

render strict -f "${strict_values}"
assert_contains "${work_dir}/strict.yaml" 'image: "ghcr.io/oxibelt/oxibelt-dataplane-strict:latest"'
assert_contains "${work_dir}/strict.yaml" 'command: ["/usr/local/bin/oxibelt-dataplane-strict"]'
assert_contains "${work_dir}/strict.yaml" 'runAsNonRoot: true'
assert_contains "${work_dir}/strict.yaml" 'readOnlyRootFilesystem: true'
assert_contains "${work_dir}/strict.yaml" 'type: RuntimeDefault'
assert_contains "${work_dir}/strict.yaml" '[runtime.hardening.seccomp]'
assert_contains "${work_dir}/strict.yaml" 'expectation = "required"'
assert_contains "${work_dir}/strict.yaml" '- ALL'
assert_not_contains "${work_dir}/strict.yaml" '[admin]'
assert_not_contains "${work_dir}/strict.yaml" 'name: admin'
assert_not_contains "${work_dir}/strict.yaml" 'OXIBELT_ADMIN_TOKEN'
assert_not_contains "${work_dir}/strict.yaml" 'mountPath: /var/cache/oxibelt'
assert_not_contains "${work_dir}/strict.yaml" 'name: cache'
assert_not_contains "${work_dir}/strict.yaml" 'OXIBELT_SECCOMP_PROFILE_IDENTITY'
assert_not_contains "${work_dir}/strict.yaml" 'OXIBELT_SECCOMP_PROFILE_DIGEST'

render strict_daemonset -f "${strict_values}" --set-string workload.kind=DaemonSet
assert_contains "${work_dir}/strict_daemonset.yaml" 'kind: DaemonSet'
assert_contains "${work_dir}/strict_daemonset.yaml" 'command: ["/usr/local/bin/oxibelt-dataplane-strict"]'
assert_not_contains "${work_dir}/strict_daemonset.yaml" '[admin]'
assert_not_contains "${work_dir}/strict_daemonset.yaml" 'name: cache'

render strict_secure_profile --kube-version 1.31.14 \
  -f "${secure_values}" -f "${strict_values}"
assert_contains "${work_dir}/strict_secure_profile.yaml" 'profile = "edge-secure-medium"'
assert_contains "${work_dir}/strict_secure_profile.yaml" '/usr/local/bin/oxibelt-dataplane-strict'
assert_not_contains "${work_dir}/strict_secure_profile.yaml" '[admin]'

render strict_bounded_cache -f "${strict_values}" \
  --set-string cacheVolume.mode=enabled \
  --set-string cacheVolume.sizeLimit=128Mi
assert_contains "${work_dir}/strict_bounded_cache.yaml" 'mountPath: /var/cache/oxibelt'
assert_contains "${work_dir}/strict_bounded_cache.yaml" 'sizeLimit: "128Mi"'

operator_profile_identity="operator-profile-v1"
operator_profile_digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
render strict_local_seccomp -f "${strict_values}" \
  --set-string podSecurityContext.seccompProfile.type=Localhost \
  --set-string podSecurityContext.seccompProfile.localhostProfile=operator/profile-v1.json \
  --set-string runtimeHardening.seccomp.externalProfile.identity="${operator_profile_identity}" \
  --set-string runtimeHardening.seccomp.externalProfile.digest="${operator_profile_digest}"
assert_contains "${work_dir}/strict_local_seccomp.yaml" 'type: Localhost'
assert_contains "${work_dir}/strict_local_seccomp.yaml" 'localhostProfile: operator/profile-v1.json'
assert_contains "${work_dir}/strict_local_seccomp.yaml" "profile_identity = \"${operator_profile_identity}\""
assert_contains "${work_dir}/strict_local_seccomp.yaml" "profile_digest = \"${operator_profile_digest}\""
assert_contains "${work_dir}/strict_local_seccomp.yaml" 'name: OXIBELT_SECCOMP_PROFILE_IDENTITY'
assert_contains "${work_dir}/strict_local_seccomp.yaml" "value: \"${operator_profile_identity}\""
assert_contains "${work_dir}/strict_local_seccomp.yaml" 'name: OXIBELT_SECCOMP_PROFILE_DIGEST'
assert_contains "${work_dir}/strict_local_seccomp.yaml" "value: \"${operator_profile_digest}\""

render strict_local_seccomp_daemonset -f "${strict_values}" \
  --set-string workload.kind=DaemonSet \
  --set-string podSecurityContext.seccompProfile.type=Localhost \
  --set-string podSecurityContext.seccompProfile.localhostProfile=operator/profile-v1.json \
  --set-string runtimeHardening.seccomp.externalProfile.identity="${operator_profile_identity}" \
  --set-string runtimeHardening.seccomp.externalProfile.digest="${operator_profile_digest}"
assert_contains "${work_dir}/strict_local_seccomp_daemonset.yaml" 'kind: DaemonSet'
assert_contains "${work_dir}/strict_local_seccomp_daemonset.yaml" 'name: OXIBELT_SECCOMP_PROFILE_IDENTITY'
assert_contains "${work_dir}/strict_local_seccomp_daemonset.yaml" 'name: OXIBELT_SECCOMP_PROFILE_DIGEST'

render standalone --set-string image.role=standalone
assert_contains "${work_dir}/standalone.yaml" 'image: "ghcr.io/oxibelt/oxibelt:latest"'
assert_contains "${work_dir}/standalone.yaml" 'command: ["/usr/local/bin/oxibelt"]'

strict_digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
render strict_digest -f "${strict_values}" --set-string image.digest="${strict_digest}"
assert_contains "${work_dir}/strict_digest.yaml" "image: \"ghcr.io/oxibelt/oxibelt-dataplane-strict@${strict_digest}\""

expect_failure official_role_mismatch 'does not match image.role dataplane-strict' \
  -f "${strict_values}" \
  --set-string image.repository=ghcr.io/oxibelt/oxibelt-dataplane
expect_failure strict_admin 'does not support Admin enablement' \
  -f "${strict_values}" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token
expect_failure strict_admin_secret 'rejects Admin listener settings and Admin secret or certificate projections' \
  -f "${strict_values}" \
  --set-string admin.tokenSecretName=admin-token
expect_failure strict_admin_network_policy 'rejects networkPolicy.ingress.admin.from' \
  -f "${strict_values}" \
  --set-json 'networkPolicy.ingress.admin.from=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"management"}}}]'
expect_failure strict_inline_admin 'rejects Admin sections in config.inline' \
  -f "${strict_values}" \
  --set-string 'config.inline=[admin]\nenabled = true'
expect_failure strict_unbounded_cache 'cacheVolume.sizeLimit is required' \
  -f "${strict_values}" \
  --set-string cacheVolume.mode=enabled
expect_failure strict_writable_root 'readOnlyRootFilesystem=true' \
  -f "${strict_values}" \
  --set securityContext.readOnlyRootFilesystem=false
expect_failure strict_privileged 'allowPrivilegeEscalation=false' \
  -f "${strict_values}" \
  --set securityContext.allowPrivilegeEscalation=true
expect_failure strict_added_capability 'rejects securityContext.capabilities.add' \
  -f "${strict_values}" \
  --set-string securityContext.capabilities.add[0]=NET_ADMIN
expect_failure strict_unconfined_seccomp 'requires a RuntimeDefault or Localhost seccomp profile' \
  -f "${strict_values}" \
  --set-string podSecurityContext.seccompProfile.type=Unconfined
expect_failure strict_seccomp_expectation 'requires runtimeHardening.seccomp.expectation=required' \
  -f "${strict_values}" \
  --set-string runtimeHardening.seccomp.expectation=optional
expect_failure strict_local_seccomp_missing_assertion 'requires externalProfile.identity and digest' \
  -f "${strict_values}" \
  --set-string podSecurityContext.seccompProfile.type=Localhost \
  --set-string podSecurityContext.seccompProfile.localhostProfile=operator/profile-v1.json
expect_failure unsafe_local_seccomp_path 'localhostProfile' \
  -f "${strict_values}" \
  --set-string podSecurityContext.seccompProfile.type=Localhost \
  --set-string podSecurityContext.seccompProfile.localhostProfile=../profile-v1.json \
  --set-string runtimeHardening.seccomp.externalProfile.identity="${operator_profile_identity}" \
  --set-string runtimeHardening.seccomp.externalProfile.digest="${operator_profile_digest}"
expect_failure runtime_default_identity 'RuntimeDefault has no stable semantic identity' \
  -f "${strict_values}" \
  --set-string runtimeHardening.seccomp.externalProfile.identity="${operator_profile_identity}" \
  --set-string runtimeHardening.seccomp.externalProfile.digest="${operator_profile_digest}"
expect_failure local_seccomp_partial_assertion 'identity and digest must be set together' \
  -f "${strict_values}" \
  --set-string podSecurityContext.seccompProfile.type=Localhost \
  --set-string podSecurityContext.seccompProfile.localhostProfile=operator/profile-v1.json \
  --set-string runtimeHardening.seccomp.externalProfile.identity="${operator_profile_identity}"
expect_failure reserved_identity_env 'uses reserved hardening assertion variable OXIBELT_SECCOMP_PROFILE_IDENTITY' \
  --set-string extraEnv[0].name=OXIBELT_SECCOMP_PROFILE_IDENTITY \
  --set-string extraEnv[0].value=spoofed
expect_failure reserved_digest_env 'uses reserved hardening assertion variable OXIBELT_SECCOMP_PROFILE_DIGEST' \
  --set-string extraEnv[0].name=OXIBELT_SECCOMP_PROFILE_DIGEST \
  --set-string extraEnv[0].value=spoofed
expect_failure required_unconfined 'expectation=required cannot use an Unconfined seccomp profile' \
  --set-string runtimeHardening.seccomp.expectation=required \
  --set-string podSecurityContext.seccompProfile.type=Unconfined
expect_failure duplicate_seccomp_config 'cannot be combined with a [runtime.hardening.seccomp] section in config.inline' \
  --set-string runtimeHardening.seccomp.expectation=required \
  --set-string 'config.inline=[runtime.hardening.seccomp]\nexpectation = "required"'

echo "Helm strict data-plane checks passed"
