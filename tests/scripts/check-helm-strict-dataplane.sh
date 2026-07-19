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

for command in grep helm mktemp; do
  command -v "${command}" >/dev/null 2>&1 \
    || die "required command is unavailable: ${command}"
done

[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
[[ -f "${strict_values}" ]] || die "strict values example is unavailable: ${strict_values}"
[[ -f "${secure_values}" ]] || die "secure profile values are unavailable: ${secure_values}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-strict-dataplane.XXXXXX")"

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
assert_contains "${work_dir}/strict.yaml" '- ALL'
assert_not_contains "${work_dir}/strict.yaml" '[admin]'
assert_not_contains "${work_dir}/strict.yaml" 'name: admin'
assert_not_contains "${work_dir}/strict.yaml" 'OXIBELT_ADMIN_TOKEN'
assert_not_contains "${work_dir}/strict.yaml" 'mountPath: /var/cache/oxibelt'
assert_not_contains "${work_dir}/strict.yaml" 'name: cache'

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

render strict_local_seccomp -f "${strict_values}" \
  --set-string podSecurityContext.seccompProfile.type=Localhost \
  --set-string podSecurityContext.seccompProfile.localhostProfile=profiles/oxibelt-tokio.json
assert_contains "${work_dir}/strict_local_seccomp.yaml" 'type: Localhost'
assert_contains "${work_dir}/strict_local_seccomp.yaml" 'localhostProfile: profiles/oxibelt-tokio.json'

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

echo "Helm strict data-plane checks passed"
