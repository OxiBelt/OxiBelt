#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: verify-release-rebuild.sh \
  --image <ghcr.io/oxibelt/repository> --digest <sha256:...> \
  --revision <40-hex> --release-ref <refs/tags/X.Y.Z...> \
  --role <role> --artifact-arch <arch> --output <receipt.json>

Requires authenticated `gh`, rootless `docker`, Buildx, Trivy, Node, pnpm,
Git, jq, readelf, and Python 3. The script never uses `docker-rootful`.
USAGE
}

image=""
digest=""
revision=""
release_ref=""
role=""
artifact_arch=""
output=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --image) image="${2:-}"; shift 2 ;;
    --digest) digest="${2:-}"; shift 2 ;;
    --revision) revision="${2:-}"; shift 2 ;;
    --release-ref) release_ref="${2:-}"; shift 2 ;;
    --role) role="${2:-}"; shift 2 ;;
    --artifact-arch) artifact_arch="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done

if [[ ! "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
   [[ ! "${revision}" =~ ^[0-9a-f]{40}$ ]] ||
   [[ ! "${release_ref}" =~ ^refs/tags/[0-9]+\.[0-9]+\.[0-9]+(-beta\.[0-9]+|-build\.[0-9a-f]{8})?$ ]] ||
   [[ -z "${output}" ]]; then
  usage
  exit 2
fi

case "${role}" in
  standalone) expected_image="ghcr.io/oxibelt/oxibelt"; artifact_prefix="oxibelt" ;;
  dataplane) expected_image="ghcr.io/oxibelt/oxibelt-dataplane"; artifact_prefix="oxibelt-dataplane" ;;
  dataplane-strict) expected_image="ghcr.io/oxibelt/oxibelt-dataplane-strict"; artifact_prefix="oxibelt-dataplane-strict" ;;
  controller) expected_image="ghcr.io/oxibelt/oxibelt-gateway-controller"; artifact_prefix="oxibelt-gateway-controller" ;;
  tools) expected_image="ghcr.io/oxibelt/oxibelt-tools"; artifact_prefix="oxibelt-tools" ;;
  keysigner) expected_image="ghcr.io/oxibelt/oxibelt-keysigner"; artifact_prefix="oxibelt-keysigner" ;;
  *) usage; exit 2 ;;
esac
if [[ "${image}" != "${expected_image}" ]]; then
  echo "image ${image} does not match role ${role}: ${expected_image}" >&2
  exit 2
fi

case "${artifact_arch}" in
  amd64v2) platform="linux/amd64" ;;
  amd64) platform="linux/amd64" ;;
  amd64v4) platform="linux/amd64" ;;
  arm64) platform="linux/arm64" ;;
  riscv64) platform="linux/riscv64" ;;
  *) usage; exit 2 ;;
esac

for command in awk gh docker git jq node pnpm python3 readelf sha256sum trivy; do
  command -v "${command}" >/dev/null || {
    echo "required command is unavailable: ${command}" >&2
    exit 2
  }
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/oxibelt-rebuild-verify.XXXXXX")"
published_ref="${image}@${digest}"
published_tar="${temporary}/published.tar"
published_contract="${temporary}/published-contract.json"
published_sbom="${temporary}/published.cdx.json"
rebuilt_root="${temporary}/source"
rebuilt_output="${temporary}/rebuilt"
rebuilt_plan="${temporary}/rebuilt-plan.json"
rebuilt_sbom="${temporary}/rebuilt.cdx.json"
container_id=""
loaded_image=""
published_local="oxibelt-rebuild-published:${digest#sha256:}"
published_was_present="false"

cleanup() {
  if [[ -n "${container_id}" ]]; then
    docker rm -f -- "${container_id}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${loaded_image}" ]]; then
    docker image rm -- "${loaded_image}" >/dev/null 2>&1 || true
  fi
  docker image rm -- "${published_local}" >/dev/null 2>&1 || true
  if [[ "${published_was_present}" == "false" ]]; then
    docker image rm -- "${published_ref}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "${temporary}"
}
trap cleanup EXIT

signer_workflow="OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml"
expected_signer="https://github.com/${signer_workflow}@${release_ref}"
subject="oci://${published_ref}"
common_attestation_args=(
  "${subject}"
  --repo OxiBelt/OxiBelt
  --signer-workflow "${signer_workflow}"
  --signer-digest "${revision}"
  --source-digest "${revision}"
  --source-ref "${release_ref}"
  --cert-oidc-issuer https://token.actions.githubusercontent.com
  --deny-self-hosted-runners
  --limit 100
  --format json
)

gh attestation verify "${common_attestation_args[@]}" \
  --predicate-type https://slsa.dev/provenance/v1 >"${temporary}/provenance-attestations.json"
gh attestation verify "${common_attestation_args[@]}" \
  --predicate-type https://cyclonedx.org/bom >"${temporary}/sbom-attestations.json"
gh attestation verify "${common_attestation_args[@]}" \
  --predicate-type https://oxibelt.dev/attestations/rebuild/v1 >"${temporary}/recipe-attestations.json"

node --import tsx "${repo_root}/devops/sources/release_sbom.ts" verify \
  --attestations "${temporary}/provenance-attestations.json" \
  --subject-name "${image}" \
  --subject-digest "${digest}" \
  --signer-workflow "${expected_signer}" \
  --source-repository OxiBelt/OxiBelt \
  --source-ref "${release_ref}" \
  --source-revision "${revision}" \
  --workflow-path .github/workflows/release.yml

extract_predicate() {
  local attestations="$1"
  local predicate_type="$2"
  local destination="$3"
  node --import tsx "${repo_root}/devops/sources/rebuild_recipe.ts" extract \
    --attestations "${attestations}" \
    --subject-name "${image}" \
    --subject-digest "${digest}" \
    --signer-workflow "${expected_signer}" \
    --source-repository OxiBelt/OxiBelt \
    --source-ref "${release_ref}" \
    --source-revision "${revision}" \
    --predicate-type "${predicate_type}" \
    --output "${destination}"
}

extract_predicate "${temporary}/recipe-attestations.json" \
  https://oxibelt.dev/attestations/rebuild/v1 "${temporary}/recipe.json"
extract_predicate "${temporary}/sbom-attestations.json" \
  https://cyclonedx.org/bom "${published_sbom}"

jq -e \
  --arg image "${image}" --arg digest "${digest}" --arg revision "${revision}" \
  --arg ref "${release_ref}" --arg role "${role}" --arg arch "${artifact_arch}" \
  '.schemaVersion == 1 and .predicateType == "https://oxibelt.dev/attestations/rebuild/v1" and
   .kind == "platform" and .subject == {name: $image, digest: $digest} and
   .source.revision == $revision and .source.ref == $ref and
   .build.role == $role and .build.artifactArch == $arch and
   .output.artifactContract.schema == 2' \
  "${temporary}/recipe.json" >/dev/null
jq -S '.output.artifactContract' "${temporary}/recipe.json" >"${published_contract}"

release_version="${release_ref#refs/tags/}"
recorded_version="$(jq -r '.version' "${published_contract}")"
created="$(jq -r '.created' "${published_contract}")"
source_url="$(jq -r '.source' "${published_contract}")"
if [[ "${recorded_version}" != "${release_version}" ]] ||
   [[ ! "${created}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] ||
   [[ "${source_url}" != "https://github.com/OxiBelt/OxiBelt" ]]; then
  echo "rebuild recipe contains an invalid release identity" >&2
  exit 1
fi

if docker image inspect "${published_ref}" >/dev/null 2>&1; then
  published_was_present="true"
fi
docker pull --platform "${platform}" "${published_ref}"
docker tag "${published_ref}" "${published_local}"
docker save --output "${published_tar}" "${published_local}"

git init -q "${rebuilt_root}"
git -C "${rebuilt_root}" remote add origin https://github.com/OxiBelt/OxiBelt.git
git -C "${rebuilt_root}" fetch -q --depth=1 origin "${release_ref}"
git -C "${rebuilt_root}" checkout -q --detach FETCH_HEAD
if [[ "$(git -C "${rebuilt_root}" rev-parse HEAD)" != "${revision}" ]]; then
  echo "fresh checkout does not match ${revision}" >&2
  exit 1
fi

pnpm --dir "${rebuilt_root}" install --frozen-lockfile --ignore-scripts
if [[ "${release_version}" == *-build.* ]]; then
  release_event="push"
  release_prerelease="false"
elif [[ "${release_version}" == *-beta.* ]]; then
  release_event="release"
  release_prerelease="true"
else
  release_event="release"
  release_prerelease="false"
fi

node --import tsx "${rebuilt_root}/devops/sources/versioning.ts" \
  --workspace-path "${rebuilt_root}" \
  --manifest-path "${rebuilt_root}/Cargo.toml" \
  --package-name oxibelt \
  --lockfile-path "${rebuilt_root}/Cargo.lock" \
  --ref "${release_ref}" \
  --revision "${revision}" \
  --event-name "${release_event}" \
  --release-prerelease "${release_prerelease}" \
  --image-plan-output "${rebuilt_plan}" \
  --release-publish

mkdir -p "${rebuilt_output}"
OXIBELT_DOCKER_IMAGE_CREATED="${created}" \
OXIBELT_DOCKER_IMAGE_REF_NAME="${release_version}" \
OXIBELT_DOCKER_IMAGE_REVISION="${revision}" \
OXIBELT_DOCKER_IMAGE_SOURCE="${source_url}" \
OXIBELT_DOCKER_IMAGE_SOURCE_TREE="$(jq -r '.source_tree' "${published_contract}")" \
OXIBELT_DOCKER_IMAGE_VERSION="${release_version}" \
  "${rebuilt_root}/tests/scripts/build-docker-image-artifact.sh" \
    "${platform}" "${artifact_arch}" "${rebuilt_output}" "${role}"

rebuilt_tar="${rebuilt_output}/${artifact_prefix}-alpine-musl-${artifact_arch}.tar"
rebuilt_contract="${rebuilt_output}/${artifact_prefix}-alpine-musl-${artifact_arch}-artifact-contract.json"
rebuilt_metadata="${rebuilt_output}/${artifact_prefix}-alpine-musl-${artifact_arch}-build-metadata.json"
rebuilt_digest="$(jq -r '.image_digest' "${rebuilt_contract}")"
local_tag="$(jq -r --arg role "${role}" --arg arch "${artifact_arch}" \
  '.artifacts[] | select(.role == $role and .artifactArch == $arch) | .localTag' "${rebuilt_plan}")"

if docker image inspect "${local_tag}" >/dev/null 2>&1; then
  echo "refusing to replace pre-existing local image ${local_tag}" >&2
  exit 1
fi
docker load --input "${rebuilt_tar}" >/dev/null
loaded_image="${local_tag}"
container_id="$(docker create "${local_tag}")"
binary_inventory='[]'
while read -r binary; do
  binary_path="${temporary}/${binary}"
  docker cp "${container_id}:/usr/local/bin/${binary}" "${binary_path}"
  binary_sha="$(sha256sum "${binary_path}" | awk '{print $1}')"
  binary_inventory="$(jq -c \
    --arg name "${binary}" --arg path "/usr/local/bin/${binary}" \
    --arg version "${release_version}" --arg sha256 "${binary_sha}" \
    '. + [{name: $name, path: $path, version: $version, sha256: $sha256}]' \
    <<<"${binary_inventory}")"
done < <(jq -r --arg role "${role}" '.roles[] | select(.role == $role) | .binaries[]' "${rebuilt_plan}")
jq -n --argjson binaries "${binary_inventory}" \
  '{schemaVersion: 1, binaries: $binaries}' >"${temporary}/rebuilt-binaries.json"

trivy image --input "${rebuilt_tar}" --format cyclonedx \
  --output "${temporary}/rebuilt-raw.cdx.json"
node --import tsx "${rebuilt_root}/devops/sources/release_sbom.ts" platform \
  --image-plan "${rebuilt_plan}" \
  --trivy-sbom "${temporary}/rebuilt-raw.cdx.json" \
  --binary-inventory "${temporary}/rebuilt-binaries.json" \
  --role "${role}" \
  --artifact-arch "${artifact_arch}" \
  --image-digest "${rebuilt_digest}" \
  --build-metadata "${rebuilt_metadata}" \
  --output "${rebuilt_sbom}"

python3 "${rebuilt_root}/tests/scripts/compare-release-image-artifacts.py" \
  --published-image-tar "${published_tar}" \
  --published-contract "${published_contract}" \
  --published-sbom "${published_sbom}" \
  --published-subject-digest "${digest}" \
  --rebuilt-image-tar "${rebuilt_tar}" \
  --rebuilt-contract "${rebuilt_contract}" \
  --rebuilt-sbom "${rebuilt_sbom}" \
  --output "${output}"
