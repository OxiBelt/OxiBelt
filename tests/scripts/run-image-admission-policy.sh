#!/usr/bin/env bash
# Prove the checked-in Sigstore admission contract against the just-released
# immutable index digest. The test uses one rootless Docker-backed Minikube
# profile and always removes it.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
admission_dir="${repo_root}/deploy/admission/sigstore"
temp_root="${TMPDIR:-/tmp}"
work_dir=""
profile_name=""
trusted_images=()
reject_only=0
untrusted_image="ghcr.io/oxibelt/oxibelt@sha256:2d8e02725a33880ec416bd24b55d43e01ce32797a945d14e45e8e04fd09b546b"
timeout_seconds="${OXIBELT_IMAGE_ADMISSION_TIMEOUT_SECONDS:-420}"

policy_chart_ref="oci://ghcr.io/sigstore/helm-charts/policy-controller"
policy_chart_version="0.10.6"
policy_chart_digest="sha256:5a4f8287d505a07d4c434aa400bf1785ec5cd88dbe3bce129dbbc3baa64b4f90"
trust_chart_ref="oci://ghcr.io/github/artifact-attestations-helm-charts/trust-policies"
trust_chart_version="v0.7.0"
trust_chart_digest="sha256:b5c9a786ab94f2b624cbfe68f5cb1364a2744c4147f33dbcdce3e96600fd5a67"

die() {
  echo "Kubernetes image admission check: $*" >&2
  exit 1
}

require_command() {
  local command="$1"
  command -v "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
}

kubectl_cmd() {
  kubectl --kubeconfig "${KUBECONFIG}" "$@"
}

diagnose() {
  set +e
  echo "--- Kubernetes image admission diagnostics ---" >&2
  kubectl_cmd get pods --all-namespaces -o wide >&2
  kubectl_cmd get clusterimagepolicies.policy.sigstore.dev -o yaml >&2
  kubectl_cmd get events --all-namespaces --sort-by=.lastTimestamp >&2
  kubectl_cmd -n artifact-attestations logs deployment/policy-controller-webhook --all-containers=true --tail=160 >&2
}

cleanup() {
  local status="$?"
  set +e

  if [[ "${status}" -ne 0 && -n "${profile_name}" ]]; then
    diagnose
  fi
  if [[ -n "${profile_name}" ]]; then
    timeout --signal=INT --kill-after=10 60s \
      minikube delete --profile "${profile_name}" >/dev/null 2>&1 || true
  fi
  case "${work_dir}" in
    "${temp_root%/}"/oxibelt-image-admission.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected image admission work directory: ${work_dir}" >&2
      ;;
  esac

  exit "${status}"
}
trap cleanup EXIT

pull_chart() {
  local reference="$1"
  local version="$2"
  local expected_digest="$3"
  local output

  output="$(helm pull "${reference}" --version "${version}" --destination "${work_dir}" 2>&1)" \
    || die "failed to pull ${reference}:${version}"
  grep -F -- "Digest: ${expected_digest}" <<<"${output}" >/dev/null \
    || die "${reference}:${version} did not resolve to ${expected_digest}"
}

usage() {
  echo "Usage: $0 (--trusted-image OFFICIAL_IMAGE@sha256:<64-lowercase-hex> [...] | --reject-only) [--untrusted-image IMAGE@DIGEST]" >&2
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --trusted-image)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      trusted_images+=("$2")
      shift 2
      ;;
    --untrusted-image)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      untrusted_image="$2"
      shift 2
      ;;
    --reject-only)
      reject_only=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      die "unexpected argument: $1"
      ;;
  esac
done

if [[ "${reject_only}" -eq 1 ]]; then
  [[ "${#trusted_images[@]}" -eq 0 ]] || die "--reject-only cannot be combined with --trusted-image"
else
  [[ "${#trusted_images[@]}" -gt 0 ]] || die "at least one --trusted-image is required"
fi
[[ "${untrusted_image}" =~ ^ghcr[.]io/oxibelt/oxibelt@sha256:[0-9a-f]{64}$ ]] \
  || die "untrusted fixture must be the official OxiBelt repository at an immutable digest"
declare -A seen_trusted_images=()
for trusted_image in "${trusted_images[@]}"; do
  [[ "${trusted_image}" =~ ^ghcr[.]io/oxibelt/oxibelt(-dataplane|-gateway-controller|-tools|-keysigner)?@sha256:[0-9a-f]{64}$ ]] \
    || die "trusted image must use an exact official OxiBelt role repository and immutable digest"
  [[ "${trusted_image}" != "${untrusted_image}" ]] || die "trusted and untrusted fixtures must differ"
  [[ -z "${seen_trusted_images[${trusted_image}]:-}" ]] || die "duplicate trusted image: ${trusted_image}"
  seen_trusted_images["${trusted_image}"]=1
done
if ! [[ "${timeout_seconds}" =~ ^[0-9]+$ ]] || (( timeout_seconds < 120 || timeout_seconds > 900 )); then
  die "OXIBELT_IMAGE_ADMISSION_TIMEOUT_SECONDS must be from 120 through 900"
fi

for command in docker helm kubectl minikube grep find mktemp timeout; do
  require_command "${command}"
done

minikube_root_compatibility=()
if [[ "${EUID}" -eq 0 ]]; then
  docker info --format '{{json .SecurityOptions}}' | grep -Fq '"name=rootless"' \
    || die "refusing Minikube Docker-driver test as root unless Docker reports rootless mode"
  minikube_root_compatibility=(--force)
fi

work_dir="$(mktemp -d "${temp_root%/}/oxibelt-image-admission.XXXXXX")"
export MINIKUBE_HOME="${work_dir}/minikube-home"
export KUBECONFIG="${work_dir}/kubeconfig"
mkdir -p "${MINIKUBE_HOME}"
profile_name="oxibelt-image-admission-${RANDOM}${RANDOM}"
test_namespace="oxibelt-image-admission"

pull_chart "${policy_chart_ref}" "${policy_chart_version}" "${policy_chart_digest}"
pull_chart "${trust_chart_ref}" "${trust_chart_version}" "${trust_chart_digest}"
policy_chart="$(find "${work_dir}" -maxdepth 1 -name 'policy-controller-*.tgz' -print -quit)"
trust_chart="$(find "${work_dir}" -maxdepth 1 -name 'trust-policies-*.tgz' -print -quit)"
[[ -n "${policy_chart}" && -n "${trust_chart}" ]] || die "pulled chart archives are unavailable"

minikube_start_timeout_seconds="$((timeout_seconds + 30))"
timeout --signal=INT --kill-after=30 "${minikube_start_timeout_seconds}s" minikube start \
  --profile "${profile_name}" \
  --driver=docker \
  --container-runtime=containerd \
  --kubernetes-version=v1.31.14 \
  --output=json \
  --wait=all \
  --wait-timeout="${timeout_seconds}s" \
  "${minikube_root_compatibility[@]}" >"${work_dir}/minikube-start.log" 2>&1 \
  || { tail -n 160 "${work_dir}/minikube-start.log" >&2; die "Minikube did not start"; }

kubectl_cmd wait --for=condition=Ready node --all --timeout="${timeout_seconds}s"
helm upgrade --install policy-controller "${policy_chart}" \
  --kubeconfig "${KUBECONFIG}" \
  --namespace artifact-attestations \
  --create-namespace \
  --atomic \
  --wait \
  --timeout "${timeout_seconds}s" \
  --values "${admission_dir}/policy-controller-values.yaml"
helm upgrade --install trust-policies "${trust_chart}" \
  --kubeconfig "${KUBECONFIG}" \
  --namespace artifact-attestations \
  --atomic \
  --wait \
  --timeout "${timeout_seconds}s" \
  --values "${admission_dir}/trust-policies-values.yaml"
kubectl_cmd apply -f "${admission_dir}/oxibelt-signature-policy.yaml"
kubectl_cmd apply -f "${admission_dir}/oxibelt-provenance-policy.yaml"

kubectl_cmd create namespace "${test_namespace}"
kubectl_cmd label namespace "${test_namespace}" policy.sigstore.dev/include=true
trusted_index=0
for trusted_image in "${trusted_images[@]}"; do
  kubectl_cmd -n "${test_namespace}" create deployment "oxibelt-trusted-${trusted_index}" \
    --image="${trusted_image}" \
    --dry-run=server \
    -o yaml >"${work_dir}/trusted-${trusted_index}.yaml" \
    || die "current signed OxiBelt role digest was rejected: ${trusted_image}"
  trusted_index="$((trusted_index + 1))"
done

if kubectl_cmd -n "${test_namespace}" create deployment oxibelt-untrusted \
  --image="${untrusted_image}" \
  --dry-run=server \
  -o yaml >"${work_dir}/untrusted.yaml" 2>"${work_dir}/untrusted.log"; then
  die "unsigned OxiBelt fixture was admitted"
fi
grep -E 'denied the request|validation failed|failed policy' "${work_dir}/untrusted.log" >/dev/null \
  || { cat "${work_dir}/untrusted.log" >&2; die "untrusted fixture failed without a policy denial"; }

if [[ "${#trusted_images[@]}" -gt 0 ]]; then
  echo "Kubernetes image admission accepted ${#trusted_images[@]} signed role image(s) and rejected ${untrusted_image}."
else
  echo "Kubernetes image admission rejected ${untrusted_image}."
fi
