#!/usr/bin/env bash
# Render and validate the immutable Sigstore admission dependency and policy
# contract without creating Kubernetes resources.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
admission_dir="${repo_root}/deploy/admission/sigstore"
temp_root="${TMPDIR:-/tmp}"
work_dir=""

policy_chart_ref="oci://ghcr.io/sigstore/helm-charts/policy-controller"
policy_chart_version="0.10.6"
policy_chart_digest="sha256:5a4f8287d505a07d4c434aa400bf1785ec5cd88dbe3bce129dbbc3baa64b4f90"
trust_chart_ref="oci://ghcr.io/github/artifact-attestations-helm-charts/trust-policies"
trust_chart_version="v0.7.0"
trust_chart_digest="sha256:b5c9a786ab94f2b624cbfe68f5cb1364a2744c4147f33dbcdce3e96600fd5a67"
subject_regexp='^https://github[.]com/OxiBelt/OxiBelt/[.]github/workflows/(release|release-image-arch)[.]yml@refs/tags/(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-beta[.](0|[1-9][0-9]*)|-build[.][0-9a-f]{8})?$'

die() {
  echo "Image admission policy check: $*" >&2
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
    "${temp_root%/}"/oxibelt-image-admission-policy.*)
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

for command in helm grep find mktemp; do
  require_command "${command}"
done
for file in \
  policy-controller-values.yaml \
  trust-policies-values.yaml \
  oxibelt-signature-policy.yaml \
  oxibelt-provenance-policy.yaml; do
  [[ -f "${admission_dir}/${file}" ]] || die "admission asset is unavailable: ${file}"
done

work_dir="$(mktemp -d "${temp_root%/}/oxibelt-image-admission-policy.XXXXXX")"
pull_chart "${policy_chart_ref}" "${policy_chart_version}" "${policy_chart_digest}"
pull_chart "${trust_chart_ref}" "${trust_chart_version}" "${trust_chart_digest}"

policy_chart="$(find "${work_dir}" -maxdepth 1 -name 'policy-controller-*.tgz' -print -quit)"
trust_chart="$(find "${work_dir}" -maxdepth 1 -name 'trust-policies-*.tgz' -print -quit)"
[[ -n "${policy_chart}" && -n "${trust_chart}" ]] || die "pulled chart archives are unavailable"

helm template policy-controller "${policy_chart}" \
  --namespace artifact-attestations \
  --include-crds \
  --values "${admission_dir}/policy-controller-values.yaml" \
  >"${work_dir}/policy-controller.yaml"
helm template trust-policies "${trust_chart}" \
  --namespace artifact-attestations \
  --values "${admission_dir}/trust-policies-values.yaml" \
  >"${work_dir}/trust-policies.yaml"

assert_contains "${work_dir}/policy-controller.yaml" 'failurePolicy: Fail'
assert_contains "${work_dir}/policy-controller.yaml" 'no-match-policy: deny'
assert_contains "${work_dir}/policy-controller.yaml" 'ghcr.io/sigstore/policy-controller/policy-controller@sha256:0bcd60beb93f4427c29cf3a669743caf58490e98ded4380c33c09f092734a6ab'
assert_contains "${work_dir}/policy-controller.yaml" 'cgr.dev/chainguard/kubectl@sha256:26e2d3fb319edf7300edff25c1a64076a3bc046c9842c964d6062e9c5ee9d1d2'
assert_not_contains "${work_dir}/policy-controller.yaml" ':latest'
assert_not_contains "${work_dir}/policy-controller.yaml" ':latest-dev'

for file in \
  "${work_dir}/trust-policies.yaml" \
  "${admission_dir}/oxibelt-signature-policy.yaml" \
  "${admission_dir}/oxibelt-provenance-policy.yaml"; do
  assert_contains "${file}" 'ghcr.io/oxibelt/oxibelt@sha256:*'
  assert_contains "${file}" 'https://token.actions.githubusercontent.com'
  assert_contains "${file}" "${subject_regexp}"
done
assert_contains "${work_dir}/trust-policies.yaml" 'name: public-good'
assert_contains "${work_dir}/trust-policies.yaml" 'signatureFormat: bundle'
assert_contains "${work_dir}/trust-policies.yaml" 'predicateType: https://slsa.dev/provenance/v1'
assert_contains "${admission_dir}/oxibelt-signature-policy.yaml" 'name: oxibelt-keyless-signature'
assert_contains "${admission_dir}/oxibelt-signature-policy.yaml" 'url: https://fulcio.sigstore.dev'
assert_contains "${admission_dir}/oxibelt-signature-policy.yaml" 'url: https://rekor.sigstore.dev'
assert_contains "${admission_dir}/oxibelt-signature-policy.yaml" 'mode: enforce'
assert_not_contains "${admission_dir}/oxibelt-signature-policy.yaml" 'signatureFormat:'
assert_not_contains "${admission_dir}/oxibelt-signature-policy.yaml" 'attestations:'
assert_contains "${admission_dir}/oxibelt-provenance-policy.yaml" 'name: oxibelt-slsa-provenance'
assert_contains "${admission_dir}/oxibelt-provenance-policy.yaml" 'signatureFormat: bundle'
assert_contains "${admission_dir}/oxibelt-provenance-policy.yaml" 'name: minimum-slsa-build-level-2'
assert_contains "${admission_dir}/oxibelt-provenance-policy.yaml" 'predicateType: https://slsa.dev/provenance/v1'
assert_contains "${admission_dir}/oxibelt-provenance-policy.yaml" 'buildType: "https://actions.github.io/buildtypes/workflow/v1"'
assert_contains "${admission_dir}/oxibelt-provenance-policy.yaml" 'repository: "https://github.com/OxiBelt/OxiBelt"'
assert_contains "${admission_dir}/oxibelt-provenance-policy.yaml" 'runner_environment: "github-hosted"'
assert_contains "${admission_dir}/oxibelt-provenance-policy.yaml" 'digest: gitCommit: =~"^[0-9a-f]{40}$"'
assert_contains "${admission_dir}/oxibelt-provenance-policy.yaml" 'mode: enforce'

echo "Image admission policy assets passed static validation."
