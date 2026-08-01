#!/usr/bin/env bash
# Validate digest-pinned image rendering for both deployable OxiBelt charts.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
data_chart="${repo_root}/deploy/helm/oxibelt"
controller_chart="${repo_root}/deploy/helm/oxibelt-gateway-controller"
kubernetes_version="1.34.8"
temp_root="${TMPDIR:-/tmp}"
work_dir=""
data_image_repository="ghcr.io/oxibelt/oxibelt-dataplane"
strict_image_repository="ghcr.io/oxibelt/oxibelt-dataplane-strict"
v2_values="${data_chart}/examples/edge-secure-medium-v2-values.yaml"
controller_image_repository="ghcr.io/oxibelt/oxibelt-gateway-controller"
image_digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

die() {
  echo "Helm image digest check: $*" >&2
  exit 1
}

cleanup() {
  local status="$?"
  set +e
  case "${work_dir}" in
    "${temp_root%/}"/oxibelt-helm-image-digest.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected Helm image digest work directory: ${work_dir}" >&2
      ;;
  esac
  exit "${status}"
}
trap cleanup EXIT

command -v helm >/dev/null 2>&1 || die "required command is unavailable: helm"
work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-image-digest.XXXXXX")"

helm lint --strict "${data_chart}" \
  --kube-version "${kubernetes_version}" >"${work_dir}/data-lint.log"
helm lint --strict "${controller_chart}" \
  --kube-version "${kubernetes_version}" >"${work_dir}/controller-lint.log"

helm template oxibelt "${data_chart}" \
  --kube-version "${kubernetes_version}" >"${work_dir}/data-default.yaml"
helm template oxibelt "${data_chart}" \
  --kube-version "${kubernetes_version}" \
  --set-string image.repository="${data_image_repository}" \
  --set-string image.tag=ignored \
  --set-string image.digest="${image_digest}" \
  >"${work_dir}/data-deployment.yaml"
helm template oxibelt "${data_chart}" \
  --kube-version "${kubernetes_version}" \
  --set-string workload.kind=DaemonSet \
  --set-string image.repository="${data_image_repository}" \
  --set-string image.tag=ignored \
  --set-string image.digest="${image_digest}" \
  >"${work_dir}/data-daemonset.yaml"
helm template oxibelt "${data_chart}" \
  --kube-version "${kubernetes_version}" \
  -f "${v2_values}" \
  --set-string image.digest="${image_digest}" \
  >"${work_dir}/data-v2.yaml"
helm template oxibelt-controller "${controller_chart}" \
  --kube-version "${kubernetes_version}" \
  --set-string image.repository="${controller_image_repository}" \
  --set-string image.tag=ignored \
  --set-string image.digest="${image_digest}" \
  >"${work_dir}/controller.yaml"

grep -F -- 'image: "ghcr.io/oxibelt/oxibelt-dataplane:latest"' "${work_dir}/data-default.yaml" >/dev/null \
  || die "default data-plane image tag changed"
grep -F -- "image: \"${data_image_repository}@${image_digest}\"" "${work_dir}/data-deployment.yaml" >/dev/null \
  || die "data Deployment did not render the immutable image digest"
grep -F -- "image: \"${data_image_repository}@${image_digest}\"" "${work_dir}/data-daemonset.yaml" >/dev/null \
  || die "data DaemonSet did not render the immutable image digest"
grep -F -- "image: \"${strict_image_repository}@${image_digest}\"" "${work_dir}/data-v2.yaml" >/dev/null \
  || die "edge-secure-medium v2 did not retain the official strict digest identity"
grep -F -- "image: \"${controller_image_repository}@${image_digest}\"" "${work_dir}/controller.yaml" >/dev/null \
  || die "controller did not render the immutable image digest"
for rendered in data-deployment data-daemonset controller; do
  if grep -F -- ':ignored' "${work_dir}/${rendered}.yaml" >/dev/null; then
    die "${rendered} retained the tag when a digest was set"
  fi
done

if helm template oxibelt "${data_chart}" --kube-version "${kubernetes_version}" \
  --set-string image.digest=sha256:ABC \
  >"${work_dir}/invalid-data.log" 2>&1; then
  die "data-plane chart accepted an invalid digest"
fi
if helm template oxibelt-controller "${controller_chart}" \
  --kube-version "${kubernetes_version}" --set-string image.digest=sha256:ABC \
  >"${work_dir}/invalid-controller.log" 2>&1; then
  die "gateway controller chart accepted an invalid digest"
fi
if helm template oxibelt "${data_chart}" --kube-version "${kubernetes_version}" \
  -f "${v2_values}" --skip-schema-validation --set-string image.digest= \
  >"${work_dir}/v2-missing-digest.log" 2>&1; then
  die "edge-secure-medium v2 accepted a missing image digest"
fi
grep -F -- "OBP106-IMAGE-DIGEST" "${work_dir}/v2-missing-digest.log" >/dev/null \
  || die "edge-secure-medium v2 missing-digest diagnostic changed"
if helm template oxibelt "${data_chart}" --kube-version "${kubernetes_version}" \
  -f "${v2_values}" --skip-schema-validation \
  --set-string image.repository=ghcr.io/oxibelt/oxibelt-dataplane \
  >"${work_dir}/v2-role-confusion.log" 2>&1; then
  die "edge-secure-medium v2 accepted the compatibility repository"
fi
grep -F -- "image.repository ghcr.io/oxibelt/oxibelt-dataplane does not match image.role dataplane-strict" \
  "${work_dir}/v2-role-confusion.log" >/dev/null \
  || die "edge-secure-medium v2 role-confusion diagnostic changed"

echo "Helm image digest rendering passed."
