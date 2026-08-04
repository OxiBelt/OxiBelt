#!/usr/bin/env bash
# Validate the fail-closed edge-secure-medium v2 deployment envelope without
# reading Secret values or creating Kubernetes resources.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
profile_values="${chart_dir}/examples/edge-secure-medium-v2-values.yaml"
kubernetes_version="1.34.8"
temp_root="${TMPDIR:-/tmp}"
work_dir=""

die() {
  echo "Helm edge-secure-medium v2 check: $*" >&2
  exit 1
}

cleanup() {
  local status="$?"
  set +e
  case "${work_dir}" in
    "${temp_root%/}"/oxibelt-helm-edge-v2.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Helm v2 work directory: ${work_dir}" >&2
      ;;
  esac
  exit "${status}"
}
trap cleanup EXIT

render() {
  local name="$1"
  shift
  helm template oxibelt "${chart_dir}" --kube-version "${kubernetes_version}" \
    -f "${profile_values}" "$@" >"${work_dir}/${name}.yaml"
}

expect_failure_contains() {
  local name="$1"
  local expected="$2"
  shift 2
  if helm template oxibelt "${chart_dir}" --kube-version "${kubernetes_version}" \
    -f "${profile_values}" --skip-schema-validation "$@" \
    >"${work_dir}/${name}.log" 2>&1; then
    die "${name} unexpectedly rendered successfully"
  fi
  grep -F -- "${expected}" "${work_dir}/${name}.log" >/dev/null \
    || die "${name} did not report ${expected}"
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

annotation_value() {
  local file="$1"
  local key="$2"
  local line=""
  line="$(grep -m1 -F -- "${key}:" "${file}")" \
    || die "$(basename "${file}") is missing annotation ${key}"
  line="${line#*: }"
  line="${line#\"}"
  line="${line%\"}"
  printf '%s\n' "${line}"
}

for command in grep helm mktemp; do
  command -v "${command}" >/dev/null 2>&1 \
    || die "required command is unavailable: ${command}"
done
[[ -f "${profile_values}" ]] || die "v2 example is unavailable: ${profile_values}"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-edge-v2.XXXXXX")"

helm lint --strict "${chart_dir}" --kube-version "${kubernetes_version}" \
  -f "${profile_values}" >"${work_dir}/lint.log"

render deployment
for expected in \
  'profile = "edge-secure-medium"' \
  'profile_version = 2' \
  '[runtime.hardening.filesystem_manifest]' \
  'expected_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"' \
  'expected_writable_paths = []' \
  'image: "ghcr.io/oxibelt/oxibelt-dataplane-strict@sha256:0000000000000000000000000000000000000000000000000000000000000000"' \
  'hostNetwork: false' \
  'hostPID: false' \
  'hostIPC: false' \
  'privileged: false' \
  'automountServiceAccountToken: false' \
  'checksum/oxibelt-secret-references:' \
  'checksum/oxibelt-hardening-profile:' \
  'checksum/oxibelt-profile-report:' \
  'profile-report-' \
  '"schemaVersion": 1' \
  '"filesystemManifestExpectationPresent": true' \
  '"filesystemManifestDigestWithheld": true' \
  '"admissionRequired": true' \
  '"payloadDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"' \
  '"schemaVersion":2' \
  '"version":"oxibelt-admission-v2"' \
  '"workloadPolicy":{"schemaVersion":1,"auxiliaryContainers":[]}' \
  'oxibelt.dev/supply-chain-bundle-digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"' \
  'failurePolicy: Fail' \
  'matchPolicy: Exact' \
  'sideEffects: None' \
  '    - pods/ephemeralcontainers' \
  'automountServiceAccountToken: false' \
  'cidr: "192.0.2.1/32"' \
  '"unmetRequirements": []'; do
  assert_contains "${work_dir}/deployment.yaml" "${expected}"
done
assert_not_contains "${work_dir}/deployment.yaml" 'serviceAccountToken:'
assert_not_contains "${work_dir}/deployment.yaml" 'hostPath:'
assert_not_contains "${work_dir}/deployment.yaml" '    - pods/*'
assert_not_contains "${work_dir}/deployment.yaml" '    - */*'
assert_contains "${work_dir}/deployment.yaml" 'default-deny'

render webhook-image-rotated \
  --set-string supplyChainAdmission.webhook.image.digest=sha256:4444444444444444444444444444444444444444444444444444444444444444
baseline_admission_revision="$(annotation_value "${work_dir}/deployment.yaml" 'oxibelt.dev/supply-chain-bundle')"
rotated_admission_revision="$(annotation_value "${work_dir}/webhook-image-rotated.yaml" 'oxibelt.dev/supply-chain-bundle')"
[[ "${baseline_admission_revision}" != "${rotated_admission_revision}" ]] \
  || die "webhook image rotation did not change the admission endpoint revision"
assert_contains "${work_dir}/webhook-image-rotated.yaml" \
  'image: "ghcr.io/oxibelt/oxibelt-tools@sha256:4444444444444444444444444444444444444444444444444444444444444444"'
assert_contains "${work_dir}/webhook-image-rotated.yaml" \
  'oxibelt.dev/supply-chain-bundle-digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"'

sed \
  -e 's/"schemaVersion":2/"schemaVersion":1/' \
  -e 's/oxibelt-admission-v2/oxibelt-admission-v1/' \
  -e 's/,"workloadPolicy":{"schemaVersion":1,"auxiliaryContainers":\[\]}//' \
  -e 's/"exact_primary_evidence_verified","signed_workload_policy_verified"/"exact_evidence_verified"/' \
  "${profile_values}" >"${work_dir}/legacy-v1-values.yaml"
helm template oxibelt "${chart_dir}" --kube-version "${kubernetes_version}" \
  -f "${work_dir}/legacy-v1-values.yaml" >"${work_dir}/legacy-v1.yaml"
assert_contains "${work_dir}/legacy-v1.yaml" 'kind: ValidatingWebhookConfiguration'
assert_contains "${work_dir}/legacy-v1.yaml" '    - pods/ephemeralcontainers'

render daemonset --set-string workload.kind=DaemonSet
assert_contains "${work_dir}/daemonset.yaml" 'kind: DaemonSet'
assert_contains "${work_dir}/daemonset.yaml" 'profile_version = 2'
assert_contains "${work_dir}/daemonset.yaml" 'checksum/oxibelt-profile-report:'

render writable_emptydir \
  --set-json 'writableVolumes=[{"name":"response-cache","mountPath":"/var/cache/oxibelt","purpose":"response-cache","emptyDir":{"sizeLimit":"128Mi"}}]'
for expected in \
  'expected_writable_paths = ["/var/cache/oxibelt"]' \
  'name: response-cache' \
  'mountPath: "/var/cache/oxibelt"' \
  'sizeLimit: "128Mi"' \
  '"purpose": "response-cache"' \
  '"storage": "emptyDir"'; do
  assert_contains "${work_dir}/writable_emptydir.yaml" "${expected}"
done

render writable_pvc \
  --set-json 'writableVolumes=[{"name":"durable-state","mountPath":"/var/lib/oxibelt","purpose":"durable-state","persistentVolumeClaim":{"claimName":"oxibelt-state-v1"}}]'
assert_contains "${work_dir}/writable_pvc.yaml" 'claimName: "oxibelt-state-v1"'
assert_contains "${work_dir}/writable_pvc.yaml" '"storage": "persistentVolumeClaim"'

render unrestricted_reviewed \
  --set-json 'networkPolicy.egress.destinations=[{"name":"public-upstream","category":"upstream","unrestrictedCidrs":{"enabled":true,"justification":"reviewed public TLS origin"},"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}],"ports":[{"port":443,"protocol":"TCP"}]}]'
assert_contains "${work_dir}/unrestricted_reviewed.yaml" 'cidr: 0.0.0.0/0'
assert_contains "${work_dir}/unrestricted_reviewed.yaml" '"justification": "reviewed public TLS origin"'

render dependency_classes \
  --set-json 'networkPolicy.egress.destinations=[{"name":"upstream","category":"upstream","to":[{"ipBlock":{"cidr":"192.0.2.1/32"}}],"ports":[{"port":443,"protocol":"TCP"}]},{"name":"shared-state","category":"shared-state","to":[{"ipBlock":{"cidr":"192.0.2.2/32"}}],"ports":[{"port":6379,"protocol":"TCP"}]},{"name":"telemetry","category":"telemetry","to":[{"ipBlock":{"cidr":"192.0.2.3/32"}}],"ports":[{"port":4317,"protocol":"TCP"}]},{"name":"revocation","category":"revocation","to":[{"ipBlock":{"cidr":"192.0.2.4/32"}}],"ports":[{"port":80,"protocol":"TCP"}]},{"name":"external","category":"external-dependency","to":[{"ipBlock":{"cidr":"192.0.2.5/32"}}],"ports":[{"port":9443,"protocol":"TCP"}]}]'
for category in upstream shared-state telemetry revocation external-dependency; do
  assert_contains "${work_dir}/dependency_classes.yaml" \
    "oxibelt.dev/dependency-category: \"${category}\""
done

render kubernetes_api \
  --set kubernetesDiscovery.serviceAccountToken.enabled=true \
  --set-string kubernetesDiscovery.serviceAccountToken.audience=oxibelt-discovery \
  --set-json 'networkPolicy.egress.destinations=[{"name":"api","category":"kubernetes-api","to":[{"ipBlock":{"cidr":"192.0.2.10/32"}}],"ports":[{"port":443,"protocol":"TCP"}]}]'
assert_contains "${work_dir}/kubernetes_api.yaml" 'audience: "oxibelt-discovery"'
assert_contains "${work_dir}/kubernetes_api.yaml" 'oxibelt.dev/dependency-category: "kubernetes-api"'

render secret_reference_changed --set-string tls.secretName=oxibelt-public-tls-v2
default_config_checksum="$(annotation_value "${work_dir}/deployment.yaml" checksum/oxibelt-config)"
default_secret_checksum="$(annotation_value "${work_dir}/deployment.yaml" checksum/oxibelt-secret-references)"
default_hardening_checksum="$(annotation_value "${work_dir}/deployment.yaml" checksum/oxibelt-hardening-profile)"
changed_config_checksum="$(annotation_value "${work_dir}/secret_reference_changed.yaml" checksum/oxibelt-config)"
changed_secret_checksum="$(annotation_value "${work_dir}/secret_reference_changed.yaml" checksum/oxibelt-secret-references)"
changed_hardening_checksum="$(annotation_value "${work_dir}/secret_reference_changed.yaml" checksum/oxibelt-hardening-profile)"
[[ "${default_secret_checksum}" != "${changed_secret_checksum}" ]] \
  || die "Secret-reference checksum did not change with the TLS Secret reference"
[[ "${default_config_checksum}" == "${changed_config_checksum}" ]] \
  || die "TLS Secret reference unexpectedly changed the native configuration checksum"
[[ "${default_hardening_checksum}" == "${changed_hardening_checksum}" ]] \
  || die "TLS Secret reference unexpectedly changed the hardening checksum"

render config_changed --set-string operationalProfile.wafMode=monitor
[[ "${default_config_checksum}" != "$(annotation_value "${work_dir}/config_changed.yaml" checksum/oxibelt-config)" ]] \
  || die "configuration checksum did not change with generated configuration"

render hardening_changed \
  --set-string podSecurityContext.seccompProfile.type=Localhost \
  --set-string podSecurityContext.seccompProfile.localhostProfile=oxibelt-runtime-default-v1.json \
  --set-string runtimeHardening.seccomp.externalProfile.identity=oxibelt-runtime-default-v1 \
  --set-string runtimeHardening.seccomp.externalProfile.digest=sha256:2222222222222222222222222222222222222222222222222222222222222222
[[ "${default_hardening_checksum}" != "$(annotation_value "${work_dir}/hardening_changed.yaml" checksum/oxibelt-hardening-profile)" ]] \
  || die "hardening checksum did not change with the external seccomp identity"

expect_failure_contains missing_digest 'OBP106-IMAGE-DIGEST' \
  --set-string image.digest=
expect_failure_contains admission_disabled 'OBP204-ADMISSION-REQUIRED' \
  --set supplyChainAdmission.enabled=false
expect_failure_contains bundle_identity_mismatch 'OBP204-BUNDLE-IDENTITY' \
  --set-string supplyChainAdmission.bundle.payloadDigest=sha256:5555555555555555555555555555555555555555555555555555555555555555
expect_failure_contains bundle_artifact_mismatch 'OBP204-BUNDLE-ARTIFACT' \
  --set-string image.digest=sha256:5555555555555555555555555555555555555555555555555555555555555555
expect_failure_contains mixed_bundle_version 'OBP204-BUNDLE-VERSION' \
  --set-json 'supplyChainAdmission.bundle.inline="{\"payload\":{\"schemaVersion\":2,\"policy\":{\"version\":\"oxibelt-admission-v1\"},\"workloadPolicy\":{\"schemaVersion\":1,\"auxiliaryContainers\":[]}}}"'
expect_failure_contains missing_workload_policy 'OBP204-BUNDLE-VERSION' \
  --set-json 'supplyChainAdmission.bundle.inline="{\"payload\":{\"schemaVersion\":2,\"policy\":{\"version\":\"oxibelt-admission-v2\"}}}"'
expect_failure_contains webhook_unpinned 'OBP204-WEBHOOK-DIGEST' \
  --set-string supplyChainAdmission.webhook.image.digest=
expect_failure_contains invalid_webhook_tls_secret 'OBP204-WEBHOOK-TLS' \
  --set-string supplyChainAdmission.webhook.tlsSecretName=bad_name
expect_failure_contains missing_webhook_sources 'OBP204-WEBHOOK-SOURCES' \
  --set-json supplyChainAdmission.webhook.apiServerSourceCidrs=[]
expect_failure_contains non_strict_role 'OBP106-IMAGE-ROLE' \
  --set-string image.role=dataplane \
  --set-string image.repository=ghcr.io/oxibelt/oxibelt-dataplane
expect_failure_contains wrong_repository 'OBP106-IMAGE-REPOSITORY' \
  --set-string image.repository=example.invalid/oxibelt
expect_failure_contains policy_disabled 'OBP106-NETWORK-POLICY' \
  --set networkPolicy.enabled=false
expect_failure_contains missing_manifest 'OBP106-FILESYSTEM-MANIFEST' \
  --set-string runtimeHardening.filesystemManifest.expectedDigest=
expect_failure_contains generic_volume 'OBP106-UNTYPED-VOLUME' \
  --set-json 'extraVolumes=[{"name":"host","hostPath":{"path":"/"}}]'
expect_failure_contains unbounded_emptydir 'OBP106-EMPTYDIR-LIMIT' \
  --set-json 'writableVolumes=[{"name":"cache","mountPath":"/var/cache/oxibelt","purpose":"cache","emptyDir":{}}]'
expect_failure_contains overlapping_paths 'OBP106-WRITABLE-PATH-OVERLAP' \
  --set-json 'writableVolumes=[{"name":"one","mountPath":"/var/lib/oxibelt","purpose":"one","emptyDir":{"sizeLimit":"1Mi"}},{"name":"two","mountPath":"/var/lib/oxibelt/cache","purpose":"two","emptyDir":{"sizeLimit":"1Mi"}}]'
expect_failure_contains world_cidr 'OBP106-UNRESTRICTED-CIDR' \
  --set-json 'networkPolicy.egress.destinations=[{"name":"world","category":"upstream","to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}],"ports":[{"port":443,"protocol":"TCP"}]}]'
expect_failure_contains noncanonical_world_cidr 'OBP106-UNRESTRICTED-CIDR' \
  --set-json 'networkPolicy.egress.destinations=[{"name":"world","category":"upstream","to":[{"ipBlock":{"cidr":"0.0.0.1/0"}}],"ports":[{"port":443,"protocol":"TCP"}]}]'
expect_failure_contains world_without_reason 'OBP106-UNRESTRICTED-CIDR-JUSTIFICATION' \
  --set-json 'networkPolicy.egress.destinations=[{"name":"world","category":"upstream","unrestrictedCidrs":{"enabled":true,"justification":""},"to":[{"ipBlock":{"cidr":"::/0"}}],"ports":[{"port":443,"protocol":"TCP"}]}]'
expect_failure_contains control_plane 'OBP106-CONTROL-PLANE' \
  --set-json 'networkPolicy.egress.destinations=[{"name":"admin","category":"control-plane","to":[{"ipBlock":{"cidr":"192.0.2.1/32"}}],"ports":[{"port":8443,"protocol":"TCP"}]}]'
expect_failure_contains disabled_cilium_destination 'OBP106-CILIUM-DISABLED' \
  --set-json 'networkPolicy.cilium.fqdnDestinations=[{"name":"telemetry","category":"telemetry","matchNames":["otel.example.test"],"ports":[{"port":4317,"protocol":"TCP"}]}]'
expect_failure_contains missing_token_audience 'OBP106-TOKEN-AUDIENCE' \
  --set kubernetesDiscovery.serviceAccountToken.enabled=true \
  --set-string kubernetesDiscovery.serviceAccountToken.audience= \
  --set-json 'networkPolicy.egress.destinations=[{"name":"api","category":"kubernetes-api","to":[{"ipBlock":{"cidr":"192.0.2.1/32"}}],"ports":[{"port":443,"protocol":"TCP"}]}]'
expect_failure_contains privileged 'OBP106-PRIVILEGED' \
  --set securityContext.privileged=true
expect_failure_contains privilege_escalation 'requires securityContext.allowPrivilegeEscalation=false and readOnlyRootFilesystem=true' \
  --set securityContext.allowPrivilegeEscalation=true
expect_failure_contains writable_root 'requires securityContext.allowPrivilegeEscalation=false and readOnlyRootFilesystem=true' \
  --set securityContext.readOnlyRootFilesystem=false
expect_failure_contains capability_add 'rejects securityContext.capabilities.add' \
  --set-json 'securityContext.capabilities.add=["NET_ADMIN"]'
expect_failure_contains unconfined_seccomp 'requires a RuntimeDefault or Localhost seccomp profile' \
  --set-string podSecurityContext.seccompProfile.type=Unconfined
expect_failure_contains duplicate_rollout_env 'uses reserved hardening assertion variable OXIBELT_CONFIG_ROLLOUT_MODE' \
  --set-string extraEnv[0].name=OXIBELT_CONFIG_ROLLOUT_MODE \
  --set-string extraEnv[0].value=helm_immutable
expect_failure_contains unmasked_proc_mount 'OBP106-CONTAINER-SECURITY-KEY' \
  --set-string securityContext.procMount=Unmasked
expect_failure_contains container_seccomp_override 'OBP106-CONTAINER-SECURITY-KEY' \
  --set-string securityContext.seccompProfile.type=Unconfined
expect_failure_contains reserved_selector_label 'OBP106-RESERVED-LABEL' \
  --set-string 'podLabels.app\.kubernetes\.io/name=spoofed'
expect_failure_contains legacy_apparmor_annotation 'OBP106-RESERVED-ANNOTATION' \
  --set-string 'podAnnotations.container\.apparmor\.security\.beta\.kubernetes\.io/oxibelt=unconfined'

echo "Helm edge-secure-medium v2 check passed"
