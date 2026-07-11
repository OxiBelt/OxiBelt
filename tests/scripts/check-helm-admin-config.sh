#!/usr/bin/env bash
# Validate the semantic Admin and Redis Secret projection combinations that
# cannot be proved by static YAML/JSON parsing alone. This script never creates
# Kubernetes resources.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
production_values="${chart_dir}/examples/admin-mtls-values.yaml"
temp_root="${TMPDIR:-/tmp}"
work_dir=""

die() {
  echo "Helm Admin configuration check: $*" >&2
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
    "${temp_root%/}"/oxibelt-helm-admin.*)
      rm -rf "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Helm Admin work directory: ${work_dir}" >&2
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

for command in helm grep mktemp; do
  require_command "${command}"
done

[[ -f "${chart_dir}/Chart.yaml" ]] || die "chart is unavailable: ${chart_dir}"
[[ -f "${production_values}" ]] || die "production Admin values example is unavailable"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-admin.XXXXXX")"

helm lint --strict "${chart_dir}" >"${work_dir}/lint.log"

render defaults
assert_not_contains "${work_dir}/defaults.yaml" "# Source: oxibelt/templates/admin-service.yaml"
assert_contains "${work_dir}/defaults.yaml" "bind = \"127.0.0.1:9092\""
assert_contains "${work_dir}/defaults.yaml" "transport = \"plaintext_allowlist\""
assert_contains "${work_dir}/defaults.yaml" "[runtime.accept]"
assert_contains "${work_dir}/defaults.yaml" "[quic.socket]"
assert_contains "${work_dir}/defaults.yaml" "reuse_port = true"

render loopback_plaintext \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token
assert_contains "${work_dir}/loopback_plaintext.yaml" "transport = \"plaintext_allowlist\""

render production_mtls -f "${production_values}"
assert_contains "${work_dir}/production_mtls.yaml" "transport = \"tls\""
assert_contains "${work_dir}/production_mtls.yaml" "min_version = \"tls1.3\""
assert_contains "${work_dir}/production_mtls.yaml" "mode = \"require\""
assert_contains "${work_dir}/production_mtls.yaml" "admin-server/tls.crt"
assert_contains "${work_dir}/production_mtls.yaml" "admin-client-ca/ca.crt"
assert_contains "${work_dir}/production_mtls.yaml" "defaultMode: 288"

render production_mtls_daemonset -f "${production_values}" \
  --set-string workload.kind=DaemonSet
assert_contains "${work_dir}/production_mtls_daemonset.yaml" "kind: DaemonSet"
assert_contains "${work_dir}/production_mtls_daemonset.yaml" "admin-server/tls.key"
assert_contains "${work_dir}/production_mtls_daemonset.yaml" "readOnly: true"

render redis_acl_projection \
  --set tls.enabled=false \
  --set-string sharedState.redisSecretProjections[0].name=redis-main \
  --set-string sharedState.redisSecretProjections[0].secretName=redis-main-credentials \
  --set-string sharedState.redisSecretProjections[0].items[0].key=ca.crt \
  --set-string sharedState.redisSecretProjections[0].items[0].path=ca.pem \
  --set-string sharedState.redisSecretProjections[0].items[1].key=username \
  --set-string sharedState.redisSecretProjections[0].items[1].path=username \
  --set-string sharedState.redisSecretProjections[0].items[2].key=password \
  --set-string sharedState.redisSecretProjections[0].items[2].path=password
assert_contains "${work_dir}/redis_acl_projection.yaml" "name: \"redis-main-credentials\""
assert_contains "${work_dir}/redis_acl_projection.yaml" "path: \"redis/redis-main/ca.pem\""
assert_contains "${work_dir}/redis_acl_projection.yaml" "path: \"redis/redis-main/username\""
assert_contains "${work_dir}/redis_acl_projection.yaml" "path: \"redis/redis-main/password\""
assert_contains "${work_dir}/redis_acl_projection.yaml" "mountPath: /etc/oxibelt/cert"

render redis_acl_projection_daemonset \
  --set tls.enabled=false \
  --set-string workload.kind=DaemonSet \
  --set-string sharedState.redisSecretProjections[0].name=redis-main \
  --set-string sharedState.redisSecretProjections[0].secretName=redis-main-credentials \
  --set-string sharedState.redisSecretProjections[0].items[0].key=password \
  --set-string sharedState.redisSecretProjections[0].items[0].path=password
assert_contains "${work_dir}/redis_acl_projection_daemonset.yaml" "kind: DaemonSet"
assert_contains "${work_dir}/redis_acl_projection_daemonset.yaml" "path: \"redis/redis-main/password\""

render private_tls_bearer \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=0.0.0.0 \
  --set admin.tls.enabled=true \
  --set-string admin.tls.secretName=admin-server \
  --set-string admin.tls.serverNames[0]=admin.example.test \
  --set-string admin.mtls.enforcement=required_external
assert_contains "${work_dir}/private_tls_bearer.yaml" "transport = \"tls\""
assert_contains "${work_dir}/private_tls_bearer.yaml" "mode = \"off\""

render insecure_development \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=0.0.0.0 \
  --set admin.insecureDevelopmentMode.enabled=true \
  --set admin.service.enabled=true
assert_contains "${work_dir}/insecure_development.yaml" "transport = \"plaintext\""
assert_contains "${work_dir}/insecure_development.yaml" "allow_insecure_plaintext = true"

render optional_external \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=0.0.0.0 \
  --set admin.tls.enabled=true \
  --set-string admin.tls.secretName=admin-server \
  --set-string admin.tls.serverNames[0]=admin.example.test \
  --set admin.service.enabled=true \
  --set-string admin.service.type=LoadBalancer \
  --set-string admin.mtls.enforcement=optional
assert_contains "${chart_dir}/templates/NOTES.txt" "WARNING: the Admin Service is externally exposed without mTLS."

expect_failure nonloopback_without_tls "admin.tls.enabled is required" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=0.0.0.0

expect_failure tls_without_identity "secretName" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=0.0.0.0 \
  --set admin.tls.enabled=true \
  --set-string admin.tls.serverNames[0]=admin.example.test \
  --set admin.mtls.enabled=true \
  --set-string admin.mtls.clientCaSecretName=admin-client-ca

expect_failure tls_without_server_name "serverNames" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=0.0.0.0 \
  --set admin.tls.enabled=true \
  --set-string admin.tls.secretName=admin-server \
  --set admin.mtls.enabled=true \
  --set-string admin.mtls.clientCaSecretName=admin-client-ca

expect_failure mtls_without_tls "admin.mtls.enabled requires admin.tls.enabled=true" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set admin.mtls.enabled=true \
  --set-string admin.mtls.clientCaSecretName=admin-client-ca

expect_failure mtls_without_ca "clientCaSecretName" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=0.0.0.0 \
  --set admin.tls.enabled=true \
  --set-string admin.tls.secretName=admin-server \
  --set-string admin.tls.serverNames[0]=admin.example.test \
  --set admin.mtls.enabled=true

expect_failure external_without_required_mtls "admin.mtls.enabled is required for NodePort or LoadBalancer" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=0.0.0.0 \
  --set admin.tls.enabled=true \
  --set-string admin.tls.secretName=admin-server \
  --set-string admin.tls.serverNames[0]=admin.example.test \
  --set admin.service.enabled=true \
  --set-string admin.service.type=NodePort \
  --set-string admin.mtls.enforcement=required_external

expect_failure service_without_admin "admin.service.enabled requires admin.enabled=true" \
  --set admin.service.enabled=true

expect_failure service_on_loopback "admin.service.enabled requires a non-loopback" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set admin.service.enabled=true

expect_failure development_with_tls "admin.insecureDevelopmentMode.enabled cannot be combined" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=0.0.0.0 \
  --set admin.insecureDevelopmentMode.enabled=true \
  --set admin.tls.enabled=true \
  --set-string admin.tls.secretName=admin-server \
  --set-string admin.tls.serverNames[0]=admin.example.test

expect_failure development_external "only permits a disabled or ClusterIP" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=0.0.0.0 \
  --set admin.insecureDevelopmentMode.enabled=true \
  --set admin.service.enabled=true \
  --set-string admin.service.type=LoadBalancer

expect_failure unsupported_bind "bindAddress" \
  --set admin.enabled=true \
  --set-string admin.tokenSecretName=admin-token \
  --set-string admin.bindAddress=10.0.0.1

expect_failure invalid_certificate_mount "tls.mountPath must be the cert sibling" \
  --set-string tls.mountPath=/tmp/invalid-cert-root

expect_failure redis_secret_path_escape "items[].path must be a safe relative path" \
  --skip-schema-validation \
  --set tls.enabled=false \
  --set-string sharedState.redisSecretProjections[0].name=redis-main \
  --set-string sharedState.redisSecretProjections[0].secretName=redis-main-credentials \
  --set-string sharedState.redisSecretProjections[0].items[0].key=password \
  --set-string sharedState.redisSecretProjections[0].items[0].path=../password

echo "Helm Admin configuration check passed"
