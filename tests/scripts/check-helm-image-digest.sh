#!/usr/bin/env bash
# Validate digest-pinned image rendering for both deployable OxiBelt charts.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
data_chart="${repo_root}/deploy/helm/oxibelt"
controller_chart="${repo_root}/deploy/helm/oxibelt-gateway-controller"
temp_root="${TMPDIR:-/tmp}"
work_dir=""
data_image_repository="ghcr.io/oxibelt/oxibelt-dataplane"
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

helm lint --strict "${data_chart}" >"${work_dir}/data-lint.log"
helm lint --strict "${controller_chart}" >"${work_dir}/controller-lint.log"

helm template oxibelt "${data_chart}" >"${work_dir}/data-default.yaml"
helm template oxibelt "${data_chart}" \
  --set-string image.repository="${data_image_repository}" \
  --set-string image.tag=ignored \
  --set-string image.digest="${image_digest}" \
  >"${work_dir}/data-deployment.yaml"
helm template oxibelt "${data_chart}" \
  --set-string workload.kind=DaemonSet \
  --set-string image.repository="${data_image_repository}" \
  --set-string image.tag=ignored \
  --set-string image.digest="${image_digest}" \
  >"${work_dir}/data-daemonset.yaml"
helm template oxibelt-controller "${controller_chart}" \
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
grep -F -- "image: \"${controller_image_repository}@${image_digest}\"" "${work_dir}/controller.yaml" >/dev/null \
  || die "controller did not render the immutable image digest"
for rendered in data-deployment data-daemonset controller; do
  if grep -F -- ':ignored' "${work_dir}/${rendered}.yaml" >/dev/null; then
    die "${rendered} retained the tag when a digest was set"
  fi
done

if helm template oxibelt "${data_chart}" --set-string image.digest=sha256:ABC \
  >"${work_dir}/invalid-data.log" 2>&1; then
  die "data-plane chart accepted an invalid digest"
fi
if helm template oxibelt-controller "${controller_chart}" --set-string image.digest=sha256:ABC \
  >"${work_dir}/invalid-controller.log" 2>&1; then
  die "gateway controller chart accepted an invalid digest"
fi

echo "Helm image digest rendering passed."
