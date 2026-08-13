#!/usr/bin/env bash
# Exercise the complete edge-secure-medium v2 Helm deployment and its
# credential-free, digest-bound validating admission path. Local runs use an
# isolated rootless Minikube profile by default; CI selects the Kind adapter.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
chart_values="${chart_dir}/values.yaml"
profile_values="${chart_dir}/examples/edge-secure-medium-v2-values.yaml"
artifact_validator="${repo_root}/tests/scripts/validate-ci-image-artifact.py"
artifact_builder="${repo_root}/tests/scripts/build-docker-image-artifact.sh"
temp_root="${TMPDIR:-/tmp}"
provider="${OXIBELT_KUBERNETES_PROVIDER:-minikube}"
timeout_seconds="${OXIBELT_ADMISSION_TIMEOUT_SECONDS:-600}"
kind_node_image="${OXIBELT_ADMISSION_KIND_NODE_IMAGE:-kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256}"
minikube_kubernetes_version="${OXIBELT_ADMISSION_MINIKUBE_KUBERNETES_VERSION:-v1.34.10}"
strict_artifact_dir="${OXIBELT_ADMISSION_STRICT_ARTIFACT_DIR:-}"
tools_artifact_dir="${OXIBELT_ADMISSION_TOOLS_ARTIFACT_DIR:-}"
fixture_a_input="${OXIBELT_ADMISSION_FIXTURE_A_DIR:-}"
fixture_b_input="${OXIBELT_ADMISSION_FIXTURE_B_DIR:-}"
receipt_output="${OXIBELT_ADMISSION_RECEIPT_OUTPUT:-}"

rust_builder_image="rust:1.97.1-trixie@sha256:1bcff4befb740599103a2c7cb51058e14479b2e35e3a34a3f0dc4ede09927488"
node_builder_image="node:24-alpine3.24@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43"
runtime_image="alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"

work_dir=""
admission_config_inline=""
run_id=""
cluster_name=""
namespace=""
release_name=""
kube_context=""
cluster_attempted=0
cluster_created=0
port_forward_pid=""
rotation_probe_pid=""
bundle_switch_probe_pid=""
tools_extract_container=""
tools_extract_container_name=""
tools_extract_container_created=0
tools_seed_container=""
tools_seed_container_name=""
tools_seed_container_created=0
tools_config_volume=""
tools_config_volume_created=0
tools_cert_volume=""
tools_cert_volume_created=0
strict_source_image="oxibelt-dataplane-strict:alpine-musl-amd64"
tools_source_image="oxibelt-tools:alpine-musl-amd64"
strict_source_previous_id=""
tools_source_previous_id=""
strict_loaded_id=""
tools_loaded_id=""
strict_source_touched=0
tools_source_touched=0
artifact_source_dirty=""
artifact_build_kind=""
strict_unique_image=""
tools_unique_image=""
strict_unique_image_created=0
tools_unique_image_created=0
image_lock_dir="/tmp/oxibelt-admission-image-lock-${EUID}"
strict_digest=""
tools_digest=""
strict_config_digest=""
tools_config_digest=""
strict_official_image=""
tools_official_image=""
source_revision=""
source_tree=""
api_server_source_cidrs=""
filesystem_manifest_digest=""
fixture_a=""
fixture_b=""
public_ca_a=""
public_ca_b=""
admission_tls_secret_a=""
admission_tls_secret_b=""
rotation_barrier_service=""
rotation_barrier_label_key="oxibelt.dev/admission-rotation-barrier"

usage() {
  echo "usage: $0 [--provider kind|minikube]" >&2
}

die() {
  echo "Kubernetes supply-chain admission check: $*" >&2
  exit 1
}

require_command() {
  local command="$1"
  command -v "${command}" >/dev/null 2>&1 \
    || die "required command is unavailable: ${command}"
}

derive_admission_config_inline() {
  local output="$1"
  local config_inline_bytes required

  awk '
    BEGIN {
      config_blocks = 0
      inline_blocks = 0
      content_lines = 0
      in_config = 0
      in_inline = 0
    }
    $0 == "config:" {
      config_blocks += 1
      in_config = 1
      next
    }
    in_config && $0 == "  inline: |" {
      inline_blocks += 1
      in_inline = 1
      next
    }
    in_inline && /^    / {
      print substr($0, 5)
      content_lines += 1
      next
    }
    in_inline && $0 == "" {
      print ""
      content_lines += 1
      next
    }
    in_inline {
      in_inline = 0
      in_config = 0
    }
    in_config && /^[^[:space:]]/ {
      in_config = 0
    }
    END {
      if (config_blocks != 1 || inline_blocks != 1 || content_lines == 0) {
        exit 1
      }
    }
  ' "${chart_values}" >"${output}" \
    || die "could not extract exactly one chart config.inline block"

  [[ -f "${output}" && -s "${output}" && ! -L "${output}" ]] \
    || die "derived chart config.inline must be a nonempty regular file"
  config_inline_bytes="$(stat -c '%s' -- "${output}")" \
    || die "could not measure derived chart config.inline"
  if [[ ! "${config_inline_bytes}" =~ ^[1-9][0-9]*$ ]] \
    || ((config_inline_bytes > 262144)); then
    die "derived chart config.inline exceeds its 256 KiB bound"
  fi

  for required in \
    'include = ["conf.d/*.toml"]' \
    '[config]' \
    '[runtime.accept]' \
    '[quic]' \
    '[listeners]' \
    '[tls]' \
    '[health]' \
    '[metrics]' \
    '[circuit_breakers]'; do
    grep -Fqx "${required}" "${output}" \
      || die "derived chart config.inline is missing required baseline ${required}"
  done
  if grep -Fq '[[routes]]' "${output}"; then
    die "chart config.inline already defines a route; refusing to append the test target"
  fi

  cat >>"${output}" <<'ADMISSION_ROUTE'

[[routes]]
name = "supply-chain-admission-live"
hosts = ["edge.example.test"]
path_prefix = "/__oxibelt-supply-chain-admission"

[routes.actions.redirect]
status = 308
location_template = "/"
ADMISSION_ROUTE
  chmod 0600 "${output}"

  [[ "$(grep -Fxc '[[routes]]' "${output}")" == "1" ]] \
    || die "derived chart config.inline must contain exactly one test route"
  if grep -Eq '^[[:space:]]*(upstream|upstream_pool|static_root)[[:space:]]*=' "${output}"; then
    die "derived chart config.inline must not introduce an external serving target"
  fi
}

kube() {
  kubectl --context "${kube_context}" "$@"
}

wait_for() {
  local description="$1"
  shift
  local deadline=$((SECONDS + timeout_seconds))
  until "$@"; do
    if ((SECONDS >= deadline)); then
      die "timed out waiting for ${description}"
    fi
    sleep 1
  done
}

stop_port_forward() {
  if [[ -n "${port_forward_pid}" && "${port_forward_pid}" =~ ^[1-9][0-9]*$ ]]; then
    kill "${port_forward_pid}" >/dev/null 2>&1 || true
    wait "${port_forward_pid}" >/dev/null 2>&1 || true
  fi
  port_forward_pid=""
}

stop_rotation_probe() {
  if [[ -n "${rotation_probe_pid}" && "${rotation_probe_pid}" =~ ^[1-9][0-9]*$ ]]; then
    rm -f -- "${work_dir}/rotation-probe.running"
    wait "${rotation_probe_pid}" >/dev/null 2>&1 || true
  fi
  rotation_probe_pid=""
}

stop_bundle_switch_probe() {
  if [[ -n "${bundle_switch_probe_pid}" && "${bundle_switch_probe_pid}" =~ ^[1-9][0-9]*$ ]]; then
    rm -f -- "${work_dir}/bundle-switch-probe.running"
    wait "${bundle_switch_probe_pid}" >/dev/null 2>&1 || true
  fi
  bundle_switch_probe_pid=""
}

kind_cluster_is_owned() {
  local node owner
  local -a nodes=()
  mapfile -t nodes < <(kind get nodes --name "${cluster_name}" 2>/dev/null)
  ((${#nodes[@]} == 3)) || return 1
  for node in "${nodes[@]}"; do
    case "${node}" in
      "${cluster_name}"-control-plane|"${cluster_name}"-worker|"${cluster_name}"-worker2)
        ;;
      *)
        return 1
        ;;
    esac
    owner="$(docker container inspect \
      --format '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}' \
      "${node}" 2>/dev/null)" || return 1
    [[ "${owner}" == "${cluster_name}" ]] || return 1
  done
}

kind_cluster_cleanup_is_safe() {
  local node owner
  local -a nodes=()
  [[ "${cluster_name}" =~ ^oxibelt-admission-kind-[a-f0-9]{16}$ ]] || return 1
  kind get clusters 2>/dev/null | grep -Fqx "${cluster_name}" || return 1
  mapfile -t nodes < <(kind get nodes --name "${cluster_name}" 2>/dev/null)
  ((${#nodes[@]} > 0)) || return 1
  for node in "${nodes[@]}"; do
    case "${node}" in
      "${cluster_name}"-control-plane|"${cluster_name}"-worker|"${cluster_name}"-worker2)
        ;;
      *)
        return 1
        ;;
    esac
    owner="$(docker container inspect \
      --format '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}' \
      "${node}" 2>/dev/null)" || return 1
    [[ "${owner}" == "${cluster_name}" ]] || return 1
  done
}

diagnose() {
  set +e
  [[ -n "${kube_context}" ]] || return 0
  echo "Supply-chain admission diagnostics for ${provider}/${cluster_name}/${namespace}:" >&2
  kube get nodes -o wide >&2
  kube -n "${namespace}" get deployments,replicasets,pods,services,endpoints,networkpolicies,pdb \
    -o wide --ignore-not-found >&2
  kube get validatingwebhookconfigurations \
    -l "app.kubernetes.io/instance=${release_name}" --ignore-not-found >&2
  kube -n "${namespace}" get events --sort-by=.metadata.creationTimestamp >&2
  kube -n "${namespace}" logs -l "app.kubernetes.io/name=oxibelt-admission" \
    --all-containers=true --prefix --tail=200 >&2
  kube -n "${namespace}" logs -l "app.kubernetes.io/name=oxibelt-admission" \
    --all-containers=true --prefix --previous --tail=200 >&2
}

restore_source_image() {
  local image="$1"
  local previous_id="$2"
  local expected_id="$3"
  local current_id
  current_id="$(docker image inspect --format '{{.Id}}' "${image}" 2>/dev/null || true)"
  if [[ -z "${expected_id}" || "${current_id}" != "${expected_id}" ]]; then
    echo "refusing to restore Docker image tag without exact ownership: ${image}" >&2
    return 1
  fi
  if [[ -n "${previous_id}" ]]; then
    docker image tag "${previous_id}" "${image}" >/dev/null
  else
    docker image rm --no-prune "${image}" >/dev/null
  fi
}

tools_container_is_owned() {
  local container_id="$1"
  local expected_name="$2"
  local expected_resource="$3"
  local actual_id actual_name actual_run actual_resource
  [[ "${container_id}" =~ ^[0-9a-f]{64}$ \
    && "${expected_name}" == "oxibelt-admission-tools-${expected_resource}-${run_id}" ]] \
    || return 1
  actual_id="$(docker container inspect --format '{{.Id}}' "${container_id}" 2>/dev/null)" \
    || return 1
  actual_name="$(docker container inspect --format '{{.Name}}' "${container_id}" 2>/dev/null)" \
    || return 1
  actual_run="$(docker container inspect \
    --format '{{ index .Config.Labels "oxibelt.test.run" }}' \
    "${container_id}" 2>/dev/null)" || return 1
  actual_resource="$(docker container inspect \
    --format '{{ index .Config.Labels "oxibelt.test.resource" }}' \
    "${container_id}" 2>/dev/null)" || return 1
  [[ "${actual_id}" == "${container_id}" \
    && "${actual_name}" == "/${expected_name}" \
    && "${actual_run}" == "${run_id}" \
    && "${actual_resource}" == "${expected_resource}" ]]
}

remove_owned_tools_container() {
  local container_id="$1"
  local expected_name="$2"
  local expected_resource="$3"
  local force="${4:-0}"
  tools_container_is_owned "${container_id}" "${expected_name}" "${expected_resource}" \
    || { echo "refusing to remove tools container without exact ownership: ${expected_name}" >&2; return 1; }
  if [[ "${force}" == 1 ]]; then
    docker container rm --force "${container_id}" >/dev/null
  else
    docker container rm "${container_id}" >/dev/null
  fi
}

tools_volume_is_owned() {
  local volume="$1"
  local expected_resource="$2"
  local actual_run actual_resource
  [[ "${volume}" == "oxibelt-admission-tools-${expected_resource}-${run_id}" ]] || return 1
  actual_run="$(docker volume inspect \
    --format '{{ index .Labels "oxibelt.test.run" }}' "${volume}" 2>/dev/null)" || return 1
  actual_resource="$(docker volume inspect \
    --format '{{ index .Labels "oxibelt.test.resource" }}' "${volume}" 2>/dev/null)" || return 1
  [[ "${actual_run}" == "${run_id}" && "${actual_resource}" == "${expected_resource}" ]]
}

remove_owned_tools_volume() {
  local volume="$1"
  local expected_resource="$2"
  tools_volume_is_owned "${volume}" "${expected_resource}" \
    || { echo "refusing to remove tools volume without exact ownership: ${volume}" >&2; return 1; }
  docker volume rm "${volume}" >/dev/null
}

cleanup() {
  local status="$?"
  local cleanup_failed=0
  set +e
  stop_bundle_switch_probe
  stop_rotation_probe
  stop_port_forward

  if ((status != 0)); then
    diagnose
  fi
  if ((tools_extract_container_created == 1)) && [[ -n "${tools_extract_container}" ]]; then
    if remove_owned_tools_container "${tools_extract_container}" \
      "${tools_extract_container_name}" extract 1 >/dev/null 2>&1; then
      tools_extract_container_created=0
      tools_extract_container=""
    else
      echo "could not clean up the owned tools extraction container" >&2
      cleanup_failed=1
    fi
  fi
  if ((tools_seed_container_created == 1)) && [[ -n "${tools_seed_container}" ]]; then
    if remove_owned_tools_container "${tools_seed_container}" \
      "${tools_seed_container_name}" seed 1 >/dev/null 2>&1; then
      tools_seed_container_created=0
      tools_seed_container=""
    else
      echo "could not clean up the owned tools staging container" >&2
      cleanup_failed=1
    fi
  fi
  if ((tools_config_volume_created == 1)) && [[ -n "${tools_config_volume}" ]]; then
    if remove_owned_tools_volume "${tools_config_volume}" config >/dev/null 2>&1; then
      tools_config_volume_created=0
      tools_config_volume=""
    else
      echo "could not clean up the owned tools configuration volume" >&2
      cleanup_failed=1
    fi
  fi
  if ((tools_cert_volume_created == 1)) && [[ -n "${tools_cert_volume}" ]]; then
    if remove_owned_tools_volume "${tools_cert_volume}" cert >/dev/null 2>&1; then
      tools_cert_volume_created=0
      tools_cert_volume=""
    else
      echo "could not clean up the owned tools certificate volume" >&2
      cleanup_failed=1
    fi
  fi
  if ((cluster_attempted == 1)); then
    case "${provider}" in
      kind)
        if kind_cluster_cleanup_is_safe; then
          kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
        elif ((cluster_created == 1)) \
          || kind get clusters 2>/dev/null | grep -Fqx "${cluster_name}"; then
          echo "refusing to delete Kind cluster without exact ownership proof: ${cluster_name}" >&2
        fi
        ;;
      minikube)
        case "${cluster_name}" in
          oxibelt-admission-minikube-[a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9])
            minikube delete --profile "${cluster_name}" >/dev/null 2>&1 || true
            ;;
          *)
            echo "refusing to delete unexpected Minikube profile: ${cluster_name}" >&2
            ;;
        esac
        ;;
    esac
  fi

  if ((strict_unique_image_created == 1)) && [[ -n "${strict_unique_image}" ]]; then
    docker image rm --no-prune "${strict_unique_image}" >/dev/null 2>&1 || true
  fi
  if ((tools_unique_image_created == 1)) && [[ -n "${tools_unique_image}" ]]; then
    docker image rm --no-prune "${tools_unique_image}" >/dev/null 2>&1 || true
  fi
  if ((strict_source_touched == 1)); then
    restore_source_image \
      "${strict_source_image}" "${strict_source_previous_id}" "${strict_loaded_id}" || true
    if [[ -n "${strict_loaded_id}" && "${strict_loaded_id}" != "${strict_source_previous_id}" ]]; then
      docker image rm --no-prune "${strict_loaded_id}" >/dev/null 2>&1 || true
    fi
  fi
  if ((tools_source_touched == 1)); then
    restore_source_image \
      "${tools_source_image}" "${tools_source_previous_id}" "${tools_loaded_id}" || true
    if [[ -n "${tools_loaded_id}" && "${tools_loaded_id}" != "${tools_source_previous_id}" ]]; then
      docker image rm --no-prune "${tools_loaded_id}" >/dev/null 2>&1 || true
    fi
  fi

  case "${work_dir}" in
    "${temp_root%/}"/oxibelt-kubernetes-admission.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected admission work directory: ${work_dir}" >&2
      ;;
  esac
  if ((cleanup_failed == 1 && status == 0)); then
    status=1
  fi
  exit "${status}"
}
trap cleanup EXIT

while (($# > 0)); do
  case "$1" in
    --provider)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      provider="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

case "${provider}" in
  kind|minikube)
    ;;
  *)
    die "provider must be kind or minikube"
    ;;
esac
if [[ ! "${timeout_seconds}" =~ ^[1-9][0-9]{1,3}$ ]] \
  || ((timeout_seconds < 120 || timeout_seconds > 3600)); then
  die "OXIBELT_ADMISSION_TIMEOUT_SECONDS must be between 120 and 3600"
fi
case "${kind_node_image}" in
  kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256|\
  kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95|\
  kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5)
    ;;
  *)
    die "unapproved Kind node image: ${kind_node_image}"
    ;;
esac
[[ "${minikube_kubernetes_version}" =~ ^v1\.(34|35|36)\.[0-9]+$ ]] \
  || die "Minikube Kubernetes version must be within the supported 1.34-1.36 range"

for command in awk base64 cargo cat cp curl cut date dirname docker flock git grep head helm jq kubectl mktemp openssl python3 sed sha256sum stat tar tr uname; do
  require_command "${command}"
done
case "${provider}" in
  kind) require_command kind ;;
  minikube) require_command minikube ;;
esac
[[ -f "${chart_values}" && ! -L "${chart_values}" \
  && -f "${profile_values}" && -f "${artifact_validator}" && -x "${artifact_builder}" ]] \
  || die "required chart or artifact helpers are unavailable"
[[ "$(uname -m)" == "x86_64" ]] \
  || die "the current live harness consumes native AMD64 artifacts and requires an x86_64 host"

docker version --format '{{.Server.Version}}' >/dev/null
if [[ "${provider}" == "minikube" ]]; then
  docker info --format '{{json .SecurityOptions}}' | grep -Fq 'name=rootless' \
    || die "Minikube admission qualification requires the host rootless Docker service"
fi

source_revision="$(git -C "${repo_root}" rev-parse HEAD)"
source_tree="$(git -C "${repo_root}" rev-parse 'HEAD^{tree}')"
[[ "${source_revision}" =~ ^[0-9a-f]{40}$ && "${source_tree}" =~ ^[0-9a-f]{40}$ ]] \
  || die "current Git revision and source tree must be full lowercase hashes"

work_dir="$(mktemp -d "${temp_root%/}/oxibelt-kubernetes-admission.XXXXXX")"
admission_config_inline="${work_dir}/config.inline"
derive_admission_config_inline "${admission_config_inline}"
run_id="$(printf '%s' "${provider}:${BASHPID}:${RANDOM}:$(date +%s%N)" | sha256sum)"
run_id="${run_id:0:16}"
[[ "${run_id}" =~ ^[a-f0-9]{16}$ ]] || die "could not derive a bounded run ID"
cluster_name="oxibelt-admission-${provider}-${run_id}"
namespace="oxibelt-admission-${run_id}"
release_name="obp204-${run_id}"
rotation_barrier_service="oxibelt-admission-rotation-${run_id}"
export KUBECONFIG="${work_dir}/kubeconfig"

if [[ -z "${strict_artifact_dir}" || -z "${tools_artifact_dir}" ]]; then
  [[ -z "${strict_artifact_dir}" && -z "${tools_artifact_dir}" ]] \
    || die "strict and tools artifact directories must be supplied together"
  mkdir -p "${work_dir}/strict-artifact" "${work_dir}/tools-artifact"
  "${artifact_builder}" linux/amd64 amd64 "${work_dir}/strict-artifact" dataplane-strict
  "${artifact_builder}" linux/amd64 amd64 "${work_dir}/tools-artifact" tools
  strict_artifact_dir="${work_dir}/strict-artifact"
  tools_artifact_dir="${work_dir}/tools-artifact"
else
  [[ "${strict_artifact_dir}" == /* && "${tools_artifact_dir}" == /* \
    && ! -L "${strict_artifact_dir}" && ! -L "${tools_artifact_dir}" ]] \
    || die "artifact directories must be absolute non-symlink paths"
fi

validate_artifact() {
  local role="$1"
  local prefix="$2"
  local directory="$3"
  local archive="${directory%/}/${prefix}-alpine-musl-amd64.tar"
  local metadata="${directory%/}/${prefix}-alpine-musl-amd64-build-metadata.json"
  local contract="${directory%/}/${prefix}-alpine-musl-amd64-artifact-contract.json"
  local expected_version expected_ref expected_source_ref expected_dirty expected_kind expected_created

  [[ -f "${archive}" && -f "${metadata}" && -f "${contract}" ]] \
    || die "${role} image artifact is incomplete under ${directory}"
  jq -e \
    --arg role "${role}" \
    --arg revision "${source_revision}" \
    --arg tree "${source_tree}" '
      .schema == 3
        and .role == $role
        and .artifact_arch == "amd64"
        and .platform == "linux/amd64"
        and .revision == $revision
        and .source_tree == $tree
        and .source == "https://github.com/OxiBelt/OxiBelt"
        and (.source_dirty == "clean" or .source_dirty == "dirty")
        and (.build_kind == "git_development" or .build_kind == "tagged_development")
        and (.image_digest | test("^sha256:[0-9a-f]{64}$"))
        and .descriptor_digest == .image_digest
    ' "${contract}" >/dev/null \
    || die "${role} artifact contract does not match this source revision and role"
  expected_version="$(jq -r '.version' "${contract}")"
  expected_ref="$(jq -r '.ref_name' "${contract}")"
  expected_source_ref="$(jq -r '.source_ref' "${contract}")"
  expected_dirty="$(jq -r '.source_dirty' "${contract}")"
  if [[ -z "${artifact_source_dirty}" ]]; then
    artifact_source_dirty="${expected_dirty}"
  elif [[ "${artifact_source_dirty}" != "${expected_dirty}" ]]; then
    die "strict and tools artifact contracts disagree on source dirty state"
  fi
  expected_kind="$(jq -r '.build_kind' "${contract}")"
  if [[ -z "${artifact_build_kind}" ]]; then
    artifact_build_kind="${expected_kind}"
  elif [[ "${artifact_build_kind}" != "${expected_kind}" ]]; then
    die "strict and tools artifact contracts disagree on build kind"
  fi
  expected_created="$(jq -r '.created' "${contract}")"
  python3 "${artifact_validator}" validate \
    --image-tar "${archive}" \
    --build-metadata "${metadata}" \
    --contract "${contract}" \
    --role "${role}" \
    --artifact-arch amd64 \
    --expected-revision "${source_revision}" \
    --expected-source https://github.com/OxiBelt/OxiBelt \
    --expected-source-tree "${source_tree}" \
    --expected-version "${expected_version}" \
    --expected-ref-name "${expected_ref}" \
    --expected-source-ref "${expected_source_ref}" \
    --expected-source-dirty "${expected_dirty}" \
    --expected-build-kind "${expected_kind}" \
    --expected-created "${expected_created}" \
    --rust-builder-image "${rust_builder_image}" \
    --node-builder-image "${node_builder_image}" \
    --runtime-image "${runtime_image}" \
    --repo-root "${repo_root}"
}

validate_artifact dataplane-strict oxibelt-dataplane-strict "${strict_artifact_dir}"
validate_artifact tools oxibelt-tools "${tools_artifact_dir}"
strict_digest="$(jq -r '.image_digest' \
  "${strict_artifact_dir%/}/oxibelt-dataplane-strict-alpine-musl-amd64-artifact-contract.json")"
tools_digest="$(jq -r '.image_digest' \
  "${tools_artifact_dir%/}/oxibelt-tools-alpine-musl-amd64-artifact-contract.json")"
strict_config_digest="$(jq -r '.config_digest' \
  "${strict_artifact_dir%/}/oxibelt-dataplane-strict-alpine-musl-amd64-artifact-contract.json")"
tools_config_digest="$(jq -r '.config_digest' \
  "${tools_artifact_dir%/}/oxibelt-tools-alpine-musl-amd64-artifact-contract.json")"
[[ "${strict_digest}" =~ ^sha256:[0-9a-f]{64}$ \
  && "${tools_digest}" =~ ^sha256:[0-9a-f]{64}$ \
  && "${strict_config_digest}" =~ ^sha256:[0-9a-f]{64}$ \
  && "${tools_config_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die "validated artifact contracts did not expose exact manifest and config digests"
strict_official_image="ghcr.io/oxibelt/oxibelt-dataplane-strict@${strict_digest}"
tools_official_image="ghcr.io/oxibelt/oxibelt-tools@${tools_digest}"

if ! mkdir -m 0700 "${image_lock_dir}" 2>/dev/null; then
  [[ -d "${image_lock_dir}" && ! -L "${image_lock_dir}" ]] \
    || die "admission image lock directory is not a real directory"
fi
[[ "$(stat -c '%u:%a' "${image_lock_dir}")" == "${EUID}:700" ]] \
  || die "admission image lock directory must be owned by the current user with mode 0700"
exec 9>"${image_lock_dir}/image-tags.lock"
flock --wait "${timeout_seconds}" 9 \
  || die "timed out waiting for exclusive admission image-tag ownership"
strict_source_previous_id="$(docker image inspect --format '{{.Id}}' "${strict_source_image}" 2>/dev/null || true)"
tools_source_previous_id="$(docker image inspect --format '{{.Id}}' "${tools_source_image}" 2>/dev/null || true)"
strict_source_touched=1
docker load --input "${strict_artifact_dir%/}/oxibelt-dataplane-strict-alpine-musl-amd64.tar" >/dev/null
strict_loaded_id="$(docker image inspect --format '{{.Id}}' "${strict_source_image}")"
tools_source_touched=1
docker load --input "${tools_artifact_dir%/}/oxibelt-tools-alpine-musl-amd64.tar" >/dev/null
tools_loaded_id="$(docker image inspect --format '{{.Id}}' "${tools_source_image}")"
strict_unique_image="ghcr.io/oxibelt/oxibelt-dataplane-strict:obp204-${run_id}"
tools_unique_image="ghcr.io/oxibelt/oxibelt-tools:obp204-${run_id}"
for image in "${strict_unique_image}" "${tools_unique_image}"; do
  if docker image inspect "${image}" >/dev/null 2>&1; then
    die "refusing to overwrite unique local image tag: ${image}"
  fi
done
docker image tag "${strict_source_image}" "${strict_unique_image}"
strict_unique_image_created=1
docker image tag "${tools_source_image}" "${tools_unique_image}"
tools_unique_image_created=1
restore_source_image \
  "${strict_source_image}" "${strict_source_previous_id}" "${strict_loaded_id}" \
  || die "strict source image tag changed concurrently"
strict_source_touched=0
restore_source_image \
  "${tools_source_image}" "${tools_source_previous_id}" "${tools_loaded_id}" \
  || die "tools source image tag changed concurrently"
tools_source_touched=0
flock --unlock 9

case "${provider}" in
  kind)
    if kind get clusters | grep -Fqx "${cluster_name}"; then
      die "refusing to reuse existing Kind cluster ${cluster_name}"
    fi
    cat >"${work_dir}/kind.yaml" <<'KIND'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
KIND
    cluster_attempted=1
    kind create cluster --name "${cluster_name}" --image "${kind_node_image}" \
      --config "${work_dir}/kind.yaml" --wait "${timeout_seconds}s"
    cluster_created=1
    kube_context="kind-${cluster_name}"
    kind_cluster_is_owned || die "Kind cluster ownership or topology did not match this run"
    kind load docker-image --name "${cluster_name}" "${strict_unique_image}" "${tools_unique_image}"
    ;;
  minikube)
    minikube_root_compatibility=()
    if [[ "${EUID}" -eq 0 ]]; then
      minikube_root_compatibility=(--force)
    fi
    export MINIKUBE_HOME="${work_dir}/minikube-home"
    mkdir -p "${MINIKUBE_HOME}"
    if minikube profile list -o json 2>/dev/null \
      | jq -e --arg profile "${cluster_name}" 'any((.valid // [])[]?; .Name == $profile)' >/dev/null; then
      die "refusing to reuse existing Minikube profile ${cluster_name}"
    fi
    cluster_attempted=1
    minikube start --profile "${cluster_name}" --driver=docker --container-runtime=containerd \
      --nodes=3 --kubernetes-version="${minikube_kubernetes_version}" \
      --wait=all --wait-timeout="${timeout_seconds}s" \
      "${minikube_root_compatibility[@]}"
    cluster_created=1
    kube_context="${cluster_name}"
    minikube image load --profile "${cluster_name}" "${strict_unique_image}"
    minikube image load --profile "${cluster_name}" "${tools_unique_image}"
    ;;
esac

kube wait --for=condition=Ready node --all --timeout="${timeout_seconds}s"
kube get nodes -o json \
  | jq -e '.items | length == 3
      and all(.[]; any(.status.conditions[]?;
        .type == "Ready" and .status == "True"))' >/dev/null \
  || die "live admission qualification requires exactly three Ready Kubernetes nodes"
control_plane_nodes="$(kube get nodes -l node-role.kubernetes.io/control-plane -o json)"
# One semantic sentinel can acknowledge one API-server admission cache. Fail
# closed instead of generalizing this qualification to an HA control plane.
jq -e '.items | length == 1' >/dev/null <<<"${control_plane_nodes}" \
  || die "semantic admission cache qualification requires exactly one control-plane node"

node_image_command() {
  local node="$1"
  shift
  case "${provider}" in
    kind)
      docker exec "${node}" "$@"
      ;;
    minikube)
      minikube ssh --profile "${cluster_name}" --node "${node}" -- sudo "$@"
      ;;
  esac
}

node_image_names() {
  case "${provider}" in
    kind) kind get nodes --name "${cluster_name}" ;;
    minikube) kube get nodes -o json | jq -r '.items[].metadata.name' ;;
  esac
}

require_node_image_target() {
  local node="$1"
  local reference="$2"
  local expected_digest="$3"
  local image_list
  image_list="$(node_image_command "${node}" \
    ctr -n k8s.io images list "name==${reference}")" \
    || die "could not inspect containerd image ${reference} on node ${node}"
  awk -v expected_reference="${reference}" -v expected_digest="${expected_digest}" '
    NR == 1 { next }
    NF {
      rows += 1
      if ($1 == expected_reference && $3 == expected_digest) matches += 1
    }
    END { exit !(rows == 1 && matches == 1) }
  ' <<<"${image_list}" \
    || die "containerd image ${reference} on node ${node} did not target ${expected_digest}"
}

require_node_cri_identity() {
  local node="$1"
  local reference="$2"
  local expected_config_digest="$3"
  local required_tag="$4"
  local required_digest="$5"
  local image_json
  image_json="$(node_image_command "${node}" crictl inspecti "${reference}")" \
    || die "CRI could not inspect image ${reference} on node ${node}"
  jq -e \
    --arg config_digest "${expected_config_digest}" \
    --arg required_tag "${required_tag}" \
    --arg required_digest "${required_digest}" '
      .status.id == $config_digest
        and (((.status.repoTags // []) | index($required_tag)) != null)
        and (($required_digest == "")
          or (((.status.repoDigests // []) | index($required_digest)) != null))
    ' >/dev/null <<<"${image_json}" \
    || die "CRI image ${reference} on node ${node} did not retain its exact identity"
}

register_node_image_alias() {
  local node="$1"
  local unique_image="$2"
  local official_image="$3"
  local manifest_digest="$4"
  local config_digest="$5"
  local official_matches

  require_node_image_target "${node}" "${unique_image}" "${manifest_digest}"
  require_node_cri_identity "${node}" "${unique_image}" \
    "${config_digest}" "${unique_image}" ""

  official_matches="$(node_image_command "${node}" \
    ctr -n k8s.io images list --quiet "name==${official_image}")" \
    || die "could not check official image reference ${official_image} on node ${node}"
  [[ -z "${official_matches}" ]] \
    || die "refusing to replace pre-existing official image reference ${official_image} on node ${node}"
  if node_image_command "${node}" crictl inspecti "${official_image}" >/dev/null 2>&1; then
    die "CRI unexpectedly resolved official image reference ${official_image} on node ${node}"
  fi

  node_image_command "${node}" ctr -n k8s.io images tag --local \
    "${unique_image}" "${official_image}" >/dev/null \
    || die "could not register official image reference ${official_image} on node ${node}"
  require_node_image_target "${node}" "${official_image}" "${manifest_digest}"
  require_node_cri_identity "${node}" "${official_image}" \
    "${config_digest}" "${unique_image}" "${official_image}"
}

verify_node_images() {
  local node node_list
  node_list="$(node_image_names)" \
    || die "could not enumerate ${provider} nodes for image verification"
  [[ -n "${node_list}" ]] || die "image verification did not find any ${provider} nodes"
  while IFS= read -r node; do
    register_node_image_alias "${node}" \
      "${strict_unique_image}" "${strict_official_image}" \
      "${strict_digest}" "${strict_config_digest}"
    register_node_image_alias "${node}" \
      "${tools_unique_image}" "${tools_official_image}" \
      "${tools_digest}" "${tools_config_digest}"
  done <<<"${node_list}"
}
verify_node_images

kube create namespace "${namespace}" >/dev/null
kube label namespace "${namespace}" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted >/dev/null

api_server_source_cidrs="$(jq -c \
  '[.items[].status.addresses[] | select(.type == "InternalIP") | .address
    | if contains(":") then . + "/128" else . + "/32" end] | unique' \
  <<<"${control_plane_nodes}")"
jq -e 'length >= 1 and length <= 16 and all(.[]; test("/32$|/128$"))' \
  >/dev/null <<<"${api_server_source_cidrs}" \
  || die "could not derive exact API-server host prefixes"

generate_ca_and_server() {
  local suffix="$1"
  local extra_service_dns="${2:-}"
  local service_dns="oxibelt-admission.${namespace}.svc"
  local subject_alt_names="DNS:${service_dns},DNS:${service_dns}.cluster.local"
  if [[ -n "${extra_service_dns}" ]]; then
    subject_alt_names+=",DNS:${extra_service_dns},DNS:${extra_service_dns}.cluster.local"
  fi
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj "/CN=obp204-admission-ca-${suffix}" \
    -keyout "${work_dir}/admission-ca-${suffix}.key" \
    -out "${work_dir}/admission-ca-${suffix}.crt" >/dev/null 2>&1
  openssl req -new -newkey rsa:2048 -sha256 -nodes \
    -subj "/CN=${service_dns}" \
    -keyout "${work_dir}/admission-${suffix}.key" \
    -out "${work_dir}/admission-${suffix}.csr" >/dev/null 2>&1
  cat >"${work_dir}/admission-${suffix}.ext" <<EOF
subjectAltName=${subject_alt_names}
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF
  openssl x509 -req -sha256 -days 1 \
    -in "${work_dir}/admission-${suffix}.csr" \
    -CA "${work_dir}/admission-ca-${suffix}.crt" \
    -CAkey "${work_dir}/admission-ca-${suffix}.key" \
    -CAcreateserial -extfile "${work_dir}/admission-${suffix}.ext" \
    -out "${work_dir}/admission-${suffix}.crt" >/dev/null 2>&1
}
generate_ca_and_server a
generate_ca_and_server b "${rotation_barrier_service}.${namespace}.svc"
openssl x509 -in "${work_dir}/admission-b.crt" -noout \
  -checkhost "oxibelt-admission.${namespace}.svc" >/dev/null \
  || die "admission certificate B did not retain the canonical Service identity"
openssl x509 -in "${work_dir}/admission-b.crt" -noout \
  -checkhost "${rotation_barrier_service}.${namespace}.svc" >/dev/null \
  || die "admission certificate B did not retain the rotation barrier Service identity"
public_ca_a="$(openssl base64 -A -in "${work_dir}/admission-ca-a.crt")"
public_ca_b="$(openssl base64 -A -in "${work_dir}/admission-ca-b.crt")"
[[ -n "${public_ca_a}" && -n "${public_ca_b}" ]] || die "admission CA encoding failed"
admission_tls_secret_a="oxibelt-admission-tls-a-${run_id}"
admission_tls_secret_b="oxibelt-admission-tls-b-${run_id}"
kube -n "${namespace}" create secret tls "${admission_tls_secret_a}" \
  --cert "${work_dir}/admission-a.crt" --key "${work_dir}/admission-a.key" >/dev/null
kube -n "${namespace}" create secret tls "${admission_tls_secret_b}" \
  --cert "${work_dir}/admission-b.crt" --key "${work_dir}/admission-b.key" >/dev/null

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=edge.example.test' -addext 'subjectAltName=DNS:edge.example.test' \
  -keyout "${work_dir}/public-tls.key" -out "${work_dir}/public-tls.crt" >/dev/null 2>&1
openssl rand -base64 64 >"${work_dir}/quic-host-key.b64"
kube -n "${namespace}" create secret tls oxibelt-public-tls-v1 \
  --cert "${work_dir}/public-tls.crt" --key "${work_dir}/public-tls.key" >/dev/null
kube -n "${namespace}" create secret generic oxibelt-quic-host-key-v1 \
  --from-file="quic-host-key.b64=${work_dir}/quic-host-key.b64" >/dev/null

jq -n --arg tools "ghcr.io/oxibelt/oxibelt-tools@${tools_digest}" '{
  schemaVersion: 1,
  auxiliaryContainers: [
    {class: "regular", name: "obp204-regular", imageReference: $tools},
    {class: "init", name: "obp204-init", imageReference: $tools},
    {class: "native-sidecar", name: "obp204-native-sidecar", imageReference: $tools},
    {class: "ephemeral", name: "obp204-ephemeral", imageReference: $tools}
  ]
}' >"${work_dir}/workload-policy.json"

validate_fixture() {
  local directory="$1"
  local expected_key="$2"
  local metadata_payload_digest
  [[ "${expected_key}" =~ ^obp204-live-test-[A-Za-z0-9._-]+$ ]] \
    || die "test fixture key ID must remain visibly test-only"
  for file in bundle.json public-key.b64 revocations.json metadata.json; do
    [[ -f "${directory%/}/${file}" && ! -L "${directory%/}/${file}" ]] \
      || die "test admission fixture is missing regular file ${file}"
  done
  [[ "$(stat -c '%s' "${directory%/}/bundle.json")" -gt 0 \
    && "$(stat -c '%s' "${directory%/}/bundle.json")" -le 262144 ]] \
    || die "test admission bundle exceeds its 256 KiB input bound"
  [[ "$(stat -c '%s' "${directory%/}/revocations.json")" -gt 0 \
    && "$(stat -c '%s' "${directory%/}/revocations.json")" -le 262144 ]] \
    || die "test admission revocation set exceeds its 256 KiB input bound"
  [[ "$(stat -c '%s' "${directory%/}/metadata.json")" -gt 0 \
    && "$(stat -c '%s' "${directory%/}/metadata.json")" -le 16384 ]] \
    || die "test admission metadata exceeds its 16 KiB input bound"
  [[ "$(stat -c '%s' "${directory%/}/public-key.b64")" -eq 45 ]] \
    || die "test fixture public key must be exactly one bounded encoded key line"
  grep -Eq '^[A-Za-z0-9+/]{43}=$' "${directory%/}/public-key.b64" \
    || die "test fixture public key is not one raw Ed25519 key"
  jq -e --arg key "${expected_key}" \
    --arg primary "ghcr.io/oxibelt/oxibelt-dataplane-strict@${strict_digest}" \
    --arg tools "ghcr.io/oxibelt/oxibelt-tools@${tools_digest}" '
      .syntheticTestFixture == true
        and .keyId == $key
        and (.payloadDigest | test("^sha256:[0-9a-f]{64}$"))
        and .primaryImageReference == $primary
        and .toolsImageReference == $tools
        and (.verifiedAt | type == "number")
        and (.expiresAt | type == "number")
        and .expiresAt > .verifiedAt
        and (.expiresAt - .verifiedAt) <= 1800
    ' "${directory%/}/metadata.json" >/dev/null \
    || die "test admission fixture metadata is invalid"
  metadata_payload_digest="$(jq -r '.payloadDigest' "${directory%/}/metadata.json")"
  [[ "${metadata_payload_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || die "test fixture metadata payload digest is invalid"
  jq -e --arg digest "${strict_digest}" --arg key "${expected_key}" \
    --arg payload_digest "${metadata_payload_digest}" '
      .payload.artifact.repository == "ghcr.io/oxibelt/oxibelt-dataplane-strict"
        and .payload.artifact.role == "dataplane-strict"
        and .payload.artifact.digest == $digest
        and .signature.keyId == $key
        and .signature.payloadSha256 == $payload_digest
  ' "${directory%/}/bundle.json" >/dev/null \
    || die "test admission bundle identity does not match its metadata"
  jq -e '.schemaVersion == 1 and .revocations == []' \
    "${directory%/}/revocations.json" >/dev/null \
    || die "test admission revocation set must be empty"
}

emit_fixture() {
  local directory="$1"
  local key_id="$2"
  mkdir -m 0700 "${directory}"
  OXIBELT_TEST_ADMISSION_OUTPUT_DIR="${directory}" \
  OXIBELT_TEST_ADMISSION_PRIMARY_DIGEST="${strict_digest}" \
  OXIBELT_TEST_ADMISSION_TOOLS_DIGEST="${tools_digest}" \
  OXIBELT_TEST_ADMISSION_SOURCE_REVISION="${source_revision}" \
  OXIBELT_TEST_ADMISSION_VERIFICATION_TIME="$(date +%s)" \
  OXIBELT_TEST_ADMISSION_KEY_ID="${key_id}" \
  OXIBELT_TEST_ADMISSION_WORKLOAD_POLICY="${work_dir}/workload-policy.json" \
    cargo test --locked -p oxibeltctl --bin oxibeltctl \
      supply_chain_bundle::tests::emit_live_kubernetes_admission_fixture \
      -- --ignored --exact --nocapture
}

if [[ -n "${fixture_a_input}" || -n "${fixture_b_input}" ]]; then
  [[ -n "${fixture_a_input}" && -n "${fixture_b_input}" ]] \
    || die "fixture A and B directories must be supplied together"
  [[ "${fixture_a_input}" == /* && "${fixture_b_input}" == /* \
    && ! -L "${fixture_a_input}" && ! -L "${fixture_b_input}" ]] \
    || die "fixture input directories must be absolute non-symlink paths"
  fixture_a="${fixture_a_input}"
  fixture_b="${fixture_b_input}"
else
  fixture_a="${work_dir}/fixture-a"
  fixture_b="${work_dir}/fixture-b"
  emit_fixture "${fixture_a}" "obp204-live-test-a-${run_id}"
  emit_fixture "${fixture_b}" "obp204-live-test-b-${run_id}"
fi
fixture_key_a="$(jq -r '.keyId' "${fixture_a%/}/metadata.json")"
fixture_key_b="$(jq -r '.keyId' "${fixture_b%/}/metadata.json")"
validate_fixture "${fixture_a}" "${fixture_key_a}"
validate_fixture "${fixture_b}" "${fixture_key_b}"
bundle_digest_a="$(jq -r '.payloadDigest' "${fixture_a%/}/metadata.json")"
bundle_digest_b="$(jq -r '.payloadDigest' "${fixture_b%/}/metadata.json")"
[[ "${bundle_digest_a}" != "${bundle_digest_b}" ]] \
  || die "fixture rotation did not change the signed bundle identity"

configure_helm_args() {
  local fixture_dir="$1"
  local admission_secret="$2"
  local ca_bundle="$3"
  local manifest_digest="$4"
  local payload_digest key_id public_key
  payload_digest="$(jq -r '.payloadDigest' "${fixture_dir%/}/metadata.json")"
  key_id="$(jq -r '.keyId' "${fixture_dir%/}/metadata.json")"
  public_key="$(tr -d '\n' <"${fixture_dir%/}/public-key.b64")"
  helm_args=(
    -f "${profile_values}"
    --set-string service.type=ClusterIP
    --set-file "config.inline=${admission_config_inline}"
    --set-string "image.digest=${strict_digest}"
    --set-string image.pullPolicy=Never
    --set-string "supplyChainAdmission.bundle.payloadDigest=${payload_digest}"
    --set-file "supplyChainAdmission.bundle.inline=${fixture_dir%/}/bundle.json"
    --set-string "supplyChainAdmission.bundle.keyId=${key_id}"
    --set-string "supplyChainAdmission.bundle.publicKeyBase64=${public_key}"
    --set-file "supplyChainAdmission.bundle.revocations=${fixture_dir%/}/revocations.json"
    --set-string "supplyChainAdmission.webhook.image.digest=${tools_digest}"
    --set-string supplyChainAdmission.webhook.image.pullPolicy=Never
    --set-string "supplyChainAdmission.webhook.tlsSecretName=${admission_secret}"
    --set-json "supplyChainAdmission.webhook.apiServerSourceCidrs=${api_server_source_cidrs}"
    --set-string "supplyChainAdmission.webhook.caBundle=${ca_bundle}"
    --set-string "runtimeHardening.filesystemManifest.expectedDigest=${manifest_digest}"
  )
}

placeholder_manifest="sha256:1111111111111111111111111111111111111111111111111111111111111111"
configure_helm_args "${fixture_a}" "${admission_tls_secret_a}" "${public_ca_a}" "${placeholder_manifest}"
helm template "${release_name}" "${chart_dir}" --namespace "${namespace}" \
  --kube-version "$(kube version -o json | jq -r '.serverVersion.gitVersion' | sed 's/^v//')" \
  "${helm_args[@]}" --show-only templates/configmap.yaml >"${work_dir}/configmap.yaml"
awk '
  /^  oxibelt[.]toml: \|-$/ { in_config = 1; next }
  in_config && /^    / { sub(/^    /, ""); print; next }
  in_config { exit }
' "${work_dir}/configmap.yaml" >"${work_dir}/oxibelt.toml"
[[ -s "${work_dir}/oxibelt.toml" ]] || die "could not extract rendered native configuration"
chmod 0644 "${work_dir}/oxibelt.toml"
mkdir -m 0755 "${work_dir}/container-input"
mkdir -m 0755 "${work_dir}/container-input/config"
mkdir -m 0755 "${work_dir}/container-input/config/conf.d"
mkdir -m 0750 "${work_dir}/container-input/cert"
cp -- "${work_dir}/oxibelt.toml" "${work_dir}/container-input/config/oxibelt.toml"
cp -- "${work_dir}/public-tls.crt" "${work_dir}/container-input/cert/tls.crt"
cp -- "${work_dir}/public-tls.key" "${work_dir}/container-input/cert/tls.key"
cp -- "${work_dir}/quic-host-key.b64" \
  "${work_dir}/container-input/cert/quic-host-key.b64"
chmod 0644 "${work_dir}/container-input/config/oxibelt.toml"
chmod 0440 \
  "${work_dir}/container-input/cert/tls.crt" \
  "${work_dir}/container-input/cert/tls.key" \
  "${work_dir}/container-input/cert/quic-host-key.b64"

tools_config_volume="oxibelt-admission-tools-config-${run_id}"
tools_cert_volume="oxibelt-admission-tools-cert-${run_id}"
tools_seed_container_name="oxibelt-admission-tools-seed-${run_id}"
tools_extract_container_name="oxibelt-admission-tools-extract-${run_id}"
for volume in "${tools_config_volume}" "${tools_cert_volume}"; do
  if docker volume inspect "${volume}" >/dev/null 2>&1; then
    die "refusing to reuse existing tools input volume: ${volume}"
  fi
done
for container_name in "${tools_seed_container_name}" "${tools_extract_container_name}"; do
  if docker container inspect "${container_name}" >/dev/null 2>&1; then
    die "refusing to reuse existing tools input container: ${container_name}"
  fi
done
created_volume="$(docker volume create \
  --label "oxibelt.test.run=${run_id}" \
  --label oxibelt.test.resource=config \
  "${tools_config_volume}")"
tools_config_volume_created=1
[[ "${created_volume}" == "${tools_config_volume}" ]] \
  || die "Docker did not create the exact tools configuration volume"
tools_volume_is_owned "${tools_config_volume}" config \
  || die "tools configuration volume did not retain exact ownership labels"
created_volume="$(docker volume create \
  --label "oxibelt.test.run=${run_id}" \
  --label oxibelt.test.resource=cert \
  "${tools_cert_volume}")"
tools_cert_volume_created=1
[[ "${created_volume}" == "${tools_cert_volume}" ]] \
  || die "Docker did not create the exact tools certificate volume"
tools_volume_is_owned "${tools_cert_volume}" cert \
  || die "tools certificate volume did not retain exact ownership labels"

tools_seed_container="$(docker create --name "${tools_seed_container_name}" \
  --label "oxibelt.test.run=${run_id}" \
  --label oxibelt.test.resource=seed \
  --network none \
  --read-only \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --mount "type=volume,src=${tools_config_volume},dst=/etc/oxibelt/config,volume-nocopy" \
  --mount "type=volume,src=${tools_cert_volume},dst=/etc/oxibelt/cert,volume-nocopy" \
  --entrypoint /usr/local/bin/oxibeltctl \
  "${tools_unique_image}" --help)"
tools_seed_container_created=1
[[ "${tools_seed_container}" =~ ^[0-9a-f]{64}$ ]] \
  || die "Docker did not return an immutable tools staging container ID"
tools_container_is_owned \
  "${tools_seed_container}" "${tools_seed_container_name}" seed \
  || die "tools staging container did not retain exact ownership"
tar --format=posix --numeric-owner --owner=0 --group=10001 \
  -C "${work_dir}/container-input/config" -cf - . \
  | docker cp - "${tools_seed_container}:/etc/oxibelt/config"
tar --format=posix --numeric-owner --owner=0 --group=10001 \
  -C "${work_dir}/container-input/cert" -cf - . \
  | docker cp - "${tools_seed_container}:/etc/oxibelt/cert"

tools_extract_container="$(docker create --name "${tools_extract_container_name}" \
  --label "oxibelt.test.run=${run_id}" \
  --label oxibelt.test.resource=extract \
  --network none \
  --read-only \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --mount "type=volume,src=${tools_config_volume},dst=/etc/oxibelt/config,readonly,volume-nocopy" \
  --mount "type=volume,src=${tools_cert_volume},dst=/etc/oxibelt/cert,readonly,volume-nocopy" \
  --entrypoint /usr/local/bin/oxibeltctl \
  "${tools_unique_image}" \
  config filesystem-access /etc/oxibelt/config/oxibelt.toml \
  --format json --show-paths)"
tools_extract_container_created=1
[[ "${tools_extract_container}" =~ ^[0-9a-f]{64}$ ]] \
  || die "Docker did not return an immutable tools extraction container ID"
tools_container_is_owned \
  "${tools_extract_container}" "${tools_extract_container_name}" extract \
  || die "tools extraction container did not retain exact ownership"
docker container inspect "${tools_extract_container}" \
  | jq -e \
    --arg config_volume "${tools_config_volume}" \
    --arg cert_volume "${tools_cert_volume}" '
      length == 1
        and .[0].HostConfig.ReadonlyRootfs == true
        and .[0].HostConfig.NetworkMode == "none"
        and .[0].Config.User == "10001:10001"
        and ([.[0].Mounts[] | select(
          .Name == $config_volume
            and .Destination == "/etc/oxibelt/config"
            and .RW == false)] | length) == 1
        and ([.[0].Mounts[] | select(
          .Name == $cert_volume
            and .Destination == "/etc/oxibelt/cert"
            and .RW == false)] | length) == 1
    ' >/dev/null || die "tools extraction container did not retain its hardened mounts"
if ! docker start --attach "${tools_extract_container}" \
  >"${work_dir}/filesystem-manifest.json"; then
  extract_exit_code="$(docker container inspect \
    --format '{{.State.ExitCode}}' "${tools_extract_container}" 2>/dev/null || true)"
  die "exact tools image could not derive the filesystem manifest (exit ${extract_exit_code:-unknown})"
fi
[[ "$(docker container inspect --format '{{.State.ExitCode}}' "${tools_extract_container}")" == 0 ]] \
  || die "exact tools image could not derive the filesystem manifest"
filesystem_manifest_digest="$(jq -er '
  .manifest.schema_version as $schema
  | .manifest.normalization as $normalization
  | .manifest.manifest_digest as $digest
  | select($schema == 3)
  | select($normalization
      == "canonical_enforcement_with_verified_kubernetes_atomic_writer_digest_identity_v3")
  | select($digest | test("^sha256:[0-9a-f]{64}$"))
  | select(any(.manifest.entries[];
      .source_config_path == "config.entrypoint"
        and .path == "/etc/oxibelt/config/oxibelt.toml"))
  | select(any(.manifest.entries[];
      .source_config_path == "tls.cert_chain"
        and .path == "/etc/oxibelt/cert/tls.crt"))
  | select(any(.manifest.entries[];
      .source_config_path == "tls.private_key"
        and .path == "/etc/oxibelt/cert/tls.key"))
  | select(any(.manifest.entries[];
      .source_config_path == "quic.host_key_file"
        and .path == "/etc/oxibelt/cert/quic-host-key.b64"))
  | $digest
' "${work_dir}/filesystem-manifest.json")" \
  || die "exact tools image did not derive the required schema-v3 logical manifest entries"
remove_owned_tools_container \
  "${tools_extract_container}" "${tools_extract_container_name}" extract \
  || die "could not remove the owned tools extraction container"
tools_extract_container_created=0
tools_extract_container=""
remove_owned_tools_container \
  "${tools_seed_container}" "${tools_seed_container_name}" seed \
  || die "could not remove the owned tools staging container"
tools_seed_container_created=0
tools_seed_container=""
remove_owned_tools_volume "${tools_config_volume}" config \
  || die "could not remove the owned tools configuration volume"
tools_config_volume_created=0
tools_config_volume=""
remove_owned_tools_volume "${tools_cert_volume}" cert \
  || die "could not remove the owned tools certificate volume"
tools_cert_volume_created=0
tools_cert_volume=""
[[ "${filesystem_manifest_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die "exact tools image did not derive a filesystem manifest digest"

configure_helm_args "${fixture_a}" "${admission_tls_secret_a}" "${public_ca_a}" \
  "${filesystem_manifest_digest}"
helm upgrade --install "${release_name}" "${chart_dir}" \
  --kube-context "${kube_context}" --namespace "${namespace}" \
  "${helm_args[@]}" --atomic --wait --timeout "${timeout_seconds}s"
kube -n "${namespace}" get service oxibelt -o json \
  | jq -e '.spec.type == "ClusterIP"' >/dev/null \
  || die "data-plane Service did not remain cluster-local"

revision_for() {
  local digest="$1"
  printf 'bundle=%s\nwebhook=%s@%s' "${digest}" \
    ghcr.io/oxibelt/oxibelt-tools "${tools_digest}" | sha256sum | cut -c1-12
}
revision_a="$(revision_for "${bundle_digest_a}")"
revision_b="$(revision_for "${bundle_digest_b}")"
[[ "${revision_a}" =~ ^[a-f0-9]{12}$ && "${revision_b}" =~ ^[a-f0-9]{12}$ \
  && "${revision_a}" != "${revision_b}" ]] \
  || die "could not derive distinct admission endpoint revisions"

kube -n "${namespace}" rollout status "deployment/oxibelt-admission-${revision_a}" \
  --timeout="${timeout_seconds}s"
kube -n "${namespace}" rollout status deployment/oxibelt --timeout="${timeout_seconds}s"
kube -n "${namespace}" get deployment "oxibelt-admission-${revision_a}" -o json \
  | jq -e '.spec.replicas >= 2 and .status.readyReplicas == .spec.replicas
    and .spec.template.spec.automountServiceAccountToken == false
    and .spec.template.spec.containers[0].image
      == "ghcr.io/oxibelt/oxibelt-tools@'"${tools_digest}"'"
    and .spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem == true' \
    >/dev/null || die "admission deployment did not retain its hardened exact-image contract"
kube -n "${namespace}" get deployment oxibelt -o json \
  | jq -e --arg digest "${bundle_digest_a}" --arg image "${strict_digest}" '
      .status.readyReplicas == 3
        and .spec.template.metadata.annotations["oxibelt.dev/supply-chain-bundle-digest"] == $digest
        and .spec.template.metadata.annotations["oxibelt.dev/image-role"] == "dataplane-strict"
        and .spec.template.spec.containers[0].image
          == ("ghcr.io/oxibelt/oxibelt-dataplane-strict@" + $image)
    ' >/dev/null || die "complete v2 data plane did not become ready with exact admission identity"
mapfile -t webhook_names < <(kube get validatingwebhookconfigurations \
  -l "app.kubernetes.io/name=oxibelt-admission,app.kubernetes.io/instance=${release_name}" \
  -o json | jq -r '.items[].metadata.name')
((${#webhook_names[@]} == 1)) \
  || die "expected exactly one labeled admission webhook configuration"
webhook_name="${webhook_names[0]}"
canonical_webhook_contract() {
  local expected_ca_bundle="$1"
  kube get validatingwebhookconfiguration "${webhook_name}" -o json \
    | jq -e \
      --arg ca_bundle "${expected_ca_bundle}" \
      --arg namespace "${namespace}" \
      --arg release "${release_name}" \
      --arg webhook "${release_name}.${namespace}.supply-chain.oxibelt.dev" '
        (.webhooks | length) == 1
          and .webhooks[0].name == $webhook
          and .webhooks[0].admissionReviewVersions == ["v1"]
          and .webhooks[0].failurePolicy == "Fail"
          and .webhooks[0].matchPolicy == "Exact"
          and .webhooks[0].sideEffects == "None"
          and .webhooks[0].timeoutSeconds == 5
          and (.webhooks[0].matchConditions // []) == []
          and .webhooks[0].clientConfig.caBundle == $ca_bundle
          and .webhooks[0].clientConfig.service == {
            name: "oxibelt-admission",
            namespace: $namespace,
            path: "/validate",
            port: 443
          }
          and .webhooks[0].namespaceSelector == {
            matchLabels: {"kubernetes.io/metadata.name": $namespace}
          }
          and .webhooks[0].objectSelector == {matchLabels: {
            "app.kubernetes.io/name": "oxibelt",
            "app.kubernetes.io/instance": $release
          }}
          and .webhooks[0].rules == [{
            apiGroups: [""],
            apiVersions: ["v1"],
            operations: ["CREATE", "UPDATE"],
            resources: ["pods"],
            scope: "Namespaced"
          }, {
            apiGroups: [""],
            apiVersions: ["v1"],
            operations: ["UPDATE"],
            resources: ["pods/ephemeralcontainers"],
            scope: "Namespaced"
          }]
      ' >/dev/null
}
canonical_webhook_contract "${public_ca_a}" \
  || die "live validating webhook did not retain its exact release-scoped contract"

"${script_dir}/check-helm-edge-secure-medium-v2.sh"

port_forward_log="${work_dir}/admission-port-forward.log"
kube -n "${namespace}" port-forward service/oxibelt-admission :443 \
  >"${port_forward_log}" 2>&1 &
port_forward_pid="$!"
wait_for "admission port-forward listener" grep -Eq \
  'Forwarding from (127[.]0[.]0[.]1|\[::1\]):[0-9]+ -> 8443' "${port_forward_log}"
local_admission_port="$(sed -nE \
  's/^Forwarding from (127[.]0[.]0[.]1|\[::1\]):([0-9]+) -> 8443$/\2/p' \
  "${port_forward_log}" | head -n 1)"
[[ "${local_admission_port}" =~ ^[1-9][0-9]{3,4}$ ]] \
  || die "could not resolve the admission port-forward listener"
ready_url="https://oxibelt-admission.${namespace}.svc:${local_admission_port}/readyz"
wait_for "admission HTTPS readiness" curl --silent --show-error --fail \
  --cacert "${work_dir}/admission-ca-a.crt" \
  --resolve "oxibelt-admission.${namespace}.svc:${local_admission_port}:127.0.0.1" "${ready_url}"
stop_port_forward

base_pod() {
  local name="$1"
  local output="$2"
  kube -n "${namespace}" get deployment oxibelt -o json \
    | jq --arg name "${name}" '{
        apiVersion: "v1",
        kind: "Pod",
        metadata: {
          name: $name,
          labels: .spec.template.metadata.labels,
          annotations: .spec.template.metadata.annotations
        },
        spec: .spec.template.spec
      }' >"${output}"
}

expect_admitted() {
  local file="$1"
  kube -n "${namespace}" create --dry-run=server -f "${file}" -o name >/dev/null
}

expect_denied() {
  local name="$1"
  local file="$2"
  if kube -n "${namespace}" create --dry-run=server -f "${file}" \
    >"${work_dir}/${name}.log" 2>&1; then
    die "${name} unexpectedly passed live admission"
  fi
  grep -Fq 'SupplyChainAdmissionDenied' "${work_dir}/${name}.log" \
    || die "${name} did not return the fixed admission denial reason"
}

base_pod obp204-exact "${work_dir}/pod-exact.json"
expect_admitted "${work_dir}/pod-exact.json"
base_pod obp204-unselected-pod "${work_dir}/pod-unselected.json"
jq '
  .metadata.labels["app.kubernetes.io/name"] = "unrelated"
    | .metadata.annotations["oxibelt.dev/supply-chain-bundle-digest"] = "invalid-unselected"
    | .spec.containers[0].image = "registry.invalid/unselected:latest"
' "${work_dir}/pod-unselected.json" >"${work_dir}/pod-unselected.tmp"
mv -- "${work_dir}/pod-unselected.tmp" "${work_dir}/pod-unselected.json"
expect_admitted "${work_dir}/pod-unselected.json"
jq --arg tools "ghcr.io/oxibelt/oxibelt-tools@${tools_digest}" '
  def secure($name): {
    name: $name,
    image: $tools,
    imagePullPolicy: "Never",
    command: ["/usr/local/bin/oxibeltctl"],
    args: ["--help"],
    securityContext: {
      allowPrivilegeEscalation: false,
      readOnlyRootFilesystem: true,
      capabilities: {drop: ["ALL"]}
    }
  };
  .metadata.name = "obp204-all-classes"
  | .spec.containers += [secure("obp204-regular")]
  | .spec.initContainers = ((.spec.initContainers // [])
      + [secure("obp204-init"), (secure("obp204-native-sidecar") + {restartPolicy: "Always"})])
' "${work_dir}/pod-exact.json" >"${work_dir}/pod-all-classes.json"
expect_admitted "${work_dir}/pod-all-classes.json"

jq 'del(.metadata.annotations["oxibelt.dev/supply-chain-bundle-digest"])
  | .metadata.name = "obp204-missing-bundle"' \
  "${work_dir}/pod-exact.json" >"${work_dir}/pod-missing-bundle.json"
expect_denied missing-bundle "${work_dir}/pod-missing-bundle.json"
jq '.metadata.annotations["oxibelt.dev/supply-chain-bundle-digest"] = "sha256:'"$(printf 'f%.0s' {1..64})"'"
  | .metadata.name = "obp204-wrong-bundle"' \
  "${work_dir}/pod-exact.json" >"${work_dir}/pod-wrong-bundle.json"
expect_denied wrong-bundle "${work_dir}/pod-wrong-bundle.json"
jq '.metadata.annotations["oxibelt.dev/image-role"] = "dataplane"
  | .metadata.name = "obp204-wrong-role"' \
  "${work_dir}/pod-exact.json" >"${work_dir}/pod-wrong-role.json"
expect_denied wrong-role "${work_dir}/pod-wrong-role.json"
jq '(.spec.containers[] | select(.name == "oxibelt").image) =
      "ghcr.io/oxibelt/oxibelt-dataplane-strict@sha256:'"$(printf 'e%.0s' {1..64})"'"
  | .metadata.name = "obp204-wrong-primary"' \
  "${work_dir}/pod-exact.json" >"${work_dir}/pod-wrong-primary.json"
expect_denied wrong-primary "${work_dir}/pod-wrong-primary.json"
jq --arg image "ghcr.io/oxibelt/oxibelt-dataplane-strict:stable@${strict_digest}" '
  (.spec.containers[] | select(.name == "oxibelt").image) = $image
  | .metadata.name = "obp204-tagged-primary"' \
  "${work_dir}/pod-exact.json" >"${work_dir}/pod-tagged-primary.json"
expect_denied tagged-primary "${work_dir}/pod-tagged-primary.json"
jq --arg tools "ghcr.io/oxibelt/oxibelt-tools@${tools_digest}" '
  .metadata.name = "obp204-unlisted-aux"
  | .spec.containers += [{
      name: "unlisted", image: $tools, imagePullPolicy: "Never",
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
        capabilities: {drop: ["ALL"]}}
    }]' "${work_dir}/pod-exact.json" >"${work_dir}/pod-unlisted-aux.json"
expect_denied unlisted-aux "${work_dir}/pod-unlisted-aux.json"
jq '.metadata.name = "obp204-aux-digest-drift"
  | .spec.containers += [{
      name: "obp204-regular",
      image: "ghcr.io/oxibelt/oxibelt-tools@sha256:'"$(printf 'd%.0s' {1..64})"'",
      imagePullPolicy: "Never",
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
        capabilities: {drop: ["ALL"]}}
    }]' "${work_dir}/pod-exact.json" >"${work_dir}/pod-aux-digest-drift.json"
expect_denied aux-digest-drift "${work_dir}/pod-aux-digest-drift.json"
jq --arg tools "ghcr.io/oxibelt/oxibelt-tools@${tools_digest}" '
  .metadata.name = "obp204-class-confusion"
  | .spec.initContainers = ((.spec.initContainers // []) + [{
      name: "obp204-regular", image: $tools, imagePullPolicy: "Never",
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
        capabilities: {drop: ["ALL"]}}
    }])' "${work_dir}/pod-exact.json" >"${work_dir}/pod-class-confusion.json"
expect_denied class-confusion "${work_dir}/pod-class-confusion.json"

base_pod obp204-ephemeral-base "${work_dir}/pod-ephemeral-base.json"
kube -n "${namespace}" create -f "${work_dir}/pod-ephemeral-base.json" >/dev/null
kube -n "${namespace}" wait pod/obp204-ephemeral-base --for=condition=Ready \
  --timeout="${timeout_seconds}s"
jq -n --arg tools "ghcr.io/oxibelt/oxibelt-tools@${tools_digest}" '{spec:{ephemeralContainers:[{
  name:"obp204-ephemeral", image:$tools, imagePullPolicy:"Never",
  command:["/usr/local/bin/oxibeltctl"], args:["--help"],
  securityContext:{allowPrivilegeEscalation:false, readOnlyRootFilesystem:true,
    capabilities:{drop:["ALL"]}}
}]}}' >"${work_dir}/ephemeral-approved.json"
kube -n "${namespace}" patch pod obp204-ephemeral-base --subresource=ephemeralcontainers \
  --type merge --patch-file "${work_dir}/ephemeral-approved.json" >/dev/null
jq -n --arg tools "ghcr.io/oxibelt/oxibelt-tools@${tools_digest}" '[{
  op:"add", path:"/spec/ephemeralContainers/-",
  value:{name:"obp204-unlisted-ephemeral", image:$tools, imagePullPolicy:"Never",
    securityContext:{allowPrivilegeEscalation:false, readOnlyRootFilesystem:true,
      capabilities:{drop:["ALL"]}}}
}]' >"${work_dir}/ephemeral-denied.json"
if kube -n "${namespace}" patch pod obp204-ephemeral-base --subresource=ephemeralcontainers \
  --type json --patch-file "${work_dir}/ephemeral-denied.json" \
  >"${work_dir}/ephemeral-denied.log" 2>&1; then
  die "unlisted ephemeral container unexpectedly passed live admission"
fi
grep -Fq 'SupplyChainAdmissionDenied' "${work_dir}/ephemeral-denied.log" \
  || die "ephemeral denial did not return the fixed admission reason"
grep -Fq 'unapproved_executable_container' "${work_dir}/ephemeral-denied.log" \
  || die "ephemeral denial did not return the unapproved executable reason"

base_pod obp204-ephemeral-deny-base "${work_dir}/pod-ephemeral-deny-base.json"
kube -n "${namespace}" create -f "${work_dir}/pod-ephemeral-deny-base.json" >/dev/null
kube -n "${namespace}" wait pod/obp204-ephemeral-deny-base --for=condition=Ready \
  --timeout="${timeout_seconds}s"
expect_ephemeral_patch_denied() {
  local name="$1"
  local patch_file="$2"
  if kube -n "${namespace}" patch pod obp204-ephemeral-deny-base \
    --subresource=ephemeralcontainers --type merge --patch-file "${patch_file}" \
    >"${work_dir}/${name}.log" 2>&1; then
    die "${name} unexpectedly passed ephemeral-container admission"
  fi
  grep -Fq 'SupplyChainAdmissionDenied' "${work_dir}/${name}.log" \
    || die "${name} did not return the fixed admission denial reason"
}
jq -n '{spec:{ephemeralContainers:[{
  name:"obp204-ephemeral",
  image:"ghcr.io/oxibelt/oxibelt-tools@sha256:'"$(printf 'c%.0s' {1..64})"'",
  imagePullPolicy:"Never",
  securityContext:{allowPrivilegeEscalation:false, readOnlyRootFilesystem:true,
    capabilities:{drop:["ALL"]}}
}]}}' >"${work_dir}/ephemeral-wrong-digest.json"
expect_ephemeral_patch_denied ephemeral-wrong-digest \
  "${work_dir}/ephemeral-wrong-digest.json"
jq -n --arg tools "ghcr.io/oxibelt/oxibelt-tools@${tools_digest}" '{spec:{ephemeralContainers:[{
  name:"obp204-regular", image:$tools, imagePullPolicy:"Never",
  securityContext:{allowPrivilegeEscalation:false, readOnlyRootFilesystem:true,
    capabilities:{drop:["ALL"]}}
}]}}' >"${work_dir}/ephemeral-wrong-class.json"
expect_ephemeral_patch_denied ephemeral-wrong-class \
  "${work_dir}/ephemeral-wrong-class.json"

wrong_ca="$(openssl base64 -A -in "${work_dir}/public-tls.crt")"
kube patch validatingwebhookconfiguration "${webhook_name}" --type json \
  -p "[{\"op\":\"replace\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\"value\":\"${wrong_ca}\"}]" >/dev/null
transport_denied() {
  ! kube -n "${namespace}" create --dry-run=server -f "${work_dir}/pod-exact.json" \
    >"${work_dir}/transport-denied.log" 2>&1 \
    && grep -Eq 'failed calling webhook|certificate|x509|no endpoints available' \
      "${work_dir}/transport-denied.log"
}
wait_for "fail-closed admission TLS rejection" transport_denied
kube patch validatingwebhookconfiguration "${webhook_name}" --type json \
  -p "[{\"op\":\"replace\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\"value\":\"${public_ca_a}\"}]" >/dev/null
wait_for "admission recovery after CA restore" expect_admitted "${work_dir}/pod-exact.json"

kube -n "${namespace}" scale "deployment/oxibelt-admission-${revision_a}" --replicas=0 >/dev/null
endpoints_empty() {
  kube -n "${namespace}" get endpoints oxibelt-admission -o json \
    | jq -e '(.subsets // []) | length == 0' >/dev/null
}
wait_for "empty admission endpoints" endpoints_empty
wait_for "fail-closed admission endpoint outage" transport_denied
kube -n "${namespace}" create configmap "obp204-unrelated-${run_id}" \
  --from-literal=result=not-intercepted >/dev/null
data_pod="$(kube -n "${namespace}" get pods \
  -l "app.kubernetes.io/name=oxibelt,app.kubernetes.io/instance=${release_name}" \
  -o json | jq -r '.items[0].metadata.name')"
[[ -n "${data_pod}" && "${data_pod}" != null ]] || die "could not select a data-plane Pod"
kube -n "${namespace}" patch pod "${data_pod}" --subresource=status --type merge \
  -p '{"status":{"message":"obp204-status-subresource-not-intercepted"}}' >/dev/null
kube -n "${namespace}" scale "deployment/oxibelt-admission-${revision_a}" --replicas=2 >/dev/null
kube -n "${namespace}" rollout status "deployment/oxibelt-admission-${revision_a}" \
  --timeout="${timeout_seconds}s"
wait_for "admission recovery after endpoint outage" expect_admitted "${work_dir}/pod-exact.json"

render_admission() {
  local fixture_dir="$1"
  local tls_secret="$2"
  local ca_bundle="$3"
  local output="$4"
  configure_helm_args "${fixture_dir}" "${tls_secret}" "${ca_bundle}" \
    "${filesystem_manifest_digest}"
  helm template "${release_name}" "${chart_dir}" --namespace "${namespace}" \
    "${helm_args[@]}" \
    --show-only templates/serviceaccount.yaml \
    --show-only templates/supply-chain-admission.yaml >"${output}"
}

select_admission_documents() {
  local input="$1"
  local output="$2"
  local selection="$3"
  awk -v selection="${selection}" '
    function emit_document() {
      if (document == "") return
      is_switch = (kind == "Service" || kind == "ValidatingWebhookConfiguration")
      if ((selection == "switch" && is_switch) || (selection == "stage" && !is_switch)) {
        printf "%s", document
      }
      document = ""
      kind = ""
    }
    $0 == "---" {
      emit_document()
      document = "---\n"
      next
    }
    {
      document = document $0 "\n"
      if ($1 == "kind:") kind = $2
    }
    END { emit_document() }
  ' "${input}" >"${output}"
  [[ -s "${output}" ]] || die "admission ${selection} manifest is empty"
}

deployment_targets_tls_secret() {
  local expected_revision="$1"
  local expected_tls_secret="$2"
  local deployment_json
  deployment_json="$(kube -n "${namespace}" get deployment \
    "oxibelt-admission-${expected_revision}" -o json)" || return 1
  jq -e --arg secret "${expected_tls_secret}" '
    ([.spec.template.spec.volumes[]?
      | select(.name == "tls" and .secret.secretName == $secret)] | length) == 1
  ' >/dev/null <<<"${deployment_json}"
}

service_targets_revision_and_tls_secret() {
  local expected_revision="$1"
  local expected_tls_secret="$2"
  local expected_service="${3:-oxibelt-admission}"
  local service_json deployment_json endpoints_json desired_replicas pod_name pod_json
  service_json="$(kube -n "${namespace}" get service "${expected_service}" -o json)" \
    || return 1
  jq -e --arg revision "${expected_revision}" --arg release "${release_name}" \
    '.spec.type == "ClusterIP"
      and (.spec.ports | length) == 1
      and .spec.ports[0].name == "https"
      and .spec.ports[0].port == 443
      and .spec.ports[0].protocol == "TCP"
      and .spec.ports[0].targetPort == "https"
      and (.spec.selector | length) == 3
      and .spec.selector["app.kubernetes.io/name"] == "oxibelt-admission"
      and .spec.selector["app.kubernetes.io/instance"] == $release
      and .spec.selector["oxibelt.dev/supply-chain-bundle"] == $revision' \
    >/dev/null <<<"${service_json}" || return 1
  deployment_json="$(kube -n "${namespace}" get deployment \
    "oxibelt-admission-${expected_revision}" -o json)" || return 1
  desired_replicas="$(jq -r '.spec.replicas // 0' <<<"${deployment_json}")"
  [[ "${desired_replicas}" =~ ^[1-9][0-9]*$ ]] || return 1
  jq -e --arg revision "${expected_revision}" \
    --arg secret "${expected_tls_secret}" \
    --argjson replicas "${desired_replicas}" '
      .metadata.generation == .status.observedGeneration
        and .status.updatedReplicas == $replicas
        and .status.readyReplicas == $replicas
        and .status.availableReplicas == $replicas
        and .spec.template.metadata.labels["oxibelt.dev/supply-chain-bundle"] == $revision
        and ([.spec.template.spec.volumes[]?
          | select(.name == "tls" and .secret.secretName == $secret)] | length) == 1
    ' >/dev/null <<<"${deployment_json}" || return 1
  endpoints_json="$(kube -n "${namespace}" get endpoints "${expected_service}" -o json)" \
    || return 1
  jq -e --argjson replicas "${desired_replicas}" '
    ([.subsets[]?.addresses[]?] | length) == $replicas
      and ([.subsets[]?.addresses[]?.targetRef
        | select(.kind == "Pod"
          and (.name | type) == "string"
          and (.name | length) > 0)
        | .name] | unique | length) == $replicas
  ' >/dev/null <<<"${endpoints_json}" || return 1
  while IFS= read -r pod_name; do
    [[ -n "${pod_name}" ]] || return 1
    pod_json="$(kube -n "${namespace}" get pod "${pod_name}" -o json)" || return 1
    jq -e --arg revision "${expected_revision}" --arg secret "${expected_tls_secret}" '
      .metadata.labels["oxibelt.dev/supply-chain-bundle"] == $revision
        and any(.status.conditions[]?; .type == "Ready" and .status == "True")
        and ([.spec.volumes[]?
          | select(.name == "tls" and .secret.secretName == $secret)] | length) == 1
    ' >/dev/null <<<"${pod_json}" || return 1
  done < <(jq -r '.subsets[]?.addresses[]?.targetRef.name' <<<"${endpoints_json}")
}

webhook_trusts_exact_ca_bundle() {
  local expected_ca_bundle="$1"
  canonical_webhook_contract "${expected_ca_bundle}"
}

webhook_trusts_overlap_and_barrier() {
  local expected_ca_bundle="$1"
  local barrier_webhook="$2"
  kube get validatingwebhookconfiguration "${webhook_name}" -o json \
    | jq -e \
      --arg ca_bundle "${expected_ca_bundle}" \
      --arg ca_b "${public_ca_b}" \
      --arg barrier_webhook "${barrier_webhook}" \
      --arg barrier_service "${rotation_barrier_service}" \
      --arg namespace "${namespace}" \
      --arg release "${release_name}" \
      --arg webhook "${release_name}.${namespace}.supply-chain.oxibelt.dev" \
      --arg barrier_label_key "${rotation_barrier_label_key}" \
      --arg barrier_label_value "${run_id}" '
        (.webhooks | length) == 2
          and .webhooks[0].name == $webhook
          and .webhooks[0].admissionReviewVersions == ["v1"]
          and .webhooks[0].failurePolicy == "Fail"
          and .webhooks[0].matchPolicy == "Exact"
          and .webhooks[0].sideEffects == "None"
          and .webhooks[0].timeoutSeconds == 5
          and (.webhooks[0].matchConditions // []) == []
          and .webhooks[0].clientConfig.caBundle == $ca_bundle
          and .webhooks[0].clientConfig.service == {
            name: "oxibelt-admission",
            namespace: $namespace,
            path: "/validate",
            port: 443
          }
          and .webhooks[0].namespaceSelector == {
            matchLabels: {"kubernetes.io/metadata.name": $namespace}
          }
          and .webhooks[0].objectSelector == {matchLabels: {
            "app.kubernetes.io/name": "oxibelt",
            "app.kubernetes.io/instance": $release
          }}
          and .webhooks[0].rules == [{
            apiGroups: [""],
            apiVersions: ["v1"],
            operations: ["CREATE", "UPDATE"],
            resources: ["pods"],
            scope: "Namespaced"
          }, {
            apiGroups: [""],
            apiVersions: ["v1"],
            operations: ["UPDATE"],
            resources: ["pods/ephemeralcontainers"],
            scope: "Namespaced"
          }]
          and .webhooks[1].name == $barrier_webhook
          and .webhooks[1].admissionReviewVersions == ["v1"]
          and .webhooks[1].failurePolicy == "Fail"
          and .webhooks[1].matchPolicy == "Exact"
          and .webhooks[1].sideEffects == "None"
          and .webhooks[1].timeoutSeconds == .webhooks[0].timeoutSeconds
          and .webhooks[1].clientConfig.caBundle == $ca_b
          and .webhooks[1].clientConfig.service.name == $barrier_service
          and .webhooks[1].clientConfig.service.namespace == $namespace
          and .webhooks[1].clientConfig.service.path == "/validate"
          and .webhooks[1].clientConfig.service.port == 443
          and .webhooks[1].namespaceSelector.matchLabels["kubernetes.io/metadata.name"]
            == $namespace
          and .webhooks[1].objectSelector
            == {matchLabels: {($barrier_label_key): $barrier_label_value}}
          and .webhooks[1].rules == [{
            apiGroups: [""],
            apiVersions: ["v1"],
            operations: ["CREATE"],
            resources: ["pods"],
            scope: "Namespaced"
          }]
      ' >/dev/null
}

rotation_barrier_denied() {
  if kube -n "${namespace}" create --dry-run=server \
    -f "${work_dir}/pod-rotation-barrier.json" \
    >"${work_dir}/rotation-barrier.log" 2>&1; then
    return 1
  fi
  grep -Fq 'SupplyChainAdmissionDenied' "${work_dir}/rotation-barrier.log" \
    && grep -Fq 'bundle_digest_mismatch' "${work_dir}/rotation-barrier.log"
}

ca_overlap="$(cat "${work_dir}/admission-ca-a.crt" "${work_dir}/admission-ca-b.crt" \
  | openssl base64 -A)"
render_admission "${fixture_b}" "${admission_tls_secret_b}" "${public_ca_b}" \
  "${work_dir}/admission-bundle-b.yaml"
select_admission_documents "${work_dir}/admission-bundle-b.yaml" \
  "${work_dir}/admission-bundle-b-stage.yaml" stage
select_admission_documents "${work_dir}/admission-bundle-b.yaml" \
  "${work_dir}/admission-bundle-b-switch.yaml" switch
kube -n "${namespace}" apply -f "${work_dir}/admission-bundle-b-stage.yaml" >/dev/null
kube -n "${namespace}" rollout status "deployment/oxibelt-admission-${revision_b}" \
  --timeout="${timeout_seconds}s"

jq -n \
  --arg name "${rotation_barrier_service}" \
  --arg namespace "${namespace}" \
  --arg release "${release_name}" \
  --arg revision "${revision_b}" '{
    apiVersion: "v1",
    kind: "Service",
    metadata: {
      name: $name,
      namespace: $namespace,
      labels: {
        "app.kubernetes.io/name": "oxibelt-admission",
        "app.kubernetes.io/instance": $release,
        "oxibelt.dev/test-resource": "admission-rotation-barrier"
      }
    },
    spec: {
      type: "ClusterIP",
      selector: {
        "app.kubernetes.io/name": "oxibelt-admission",
        "app.kubernetes.io/instance": $release,
        "oxibelt.dev/supply-chain-bundle": $revision
      },
      ports: [{name: "https", port: 443, protocol: "TCP", targetPort: "https"}]
    }
  }' >"${work_dir}/rotation-barrier-service.json"
kube -n "${namespace}" create -f "${work_dir}/rotation-barrier-service.json" >/dev/null
wait_for "rotation barrier TLS Secret B endpoints" \
  service_targets_revision_and_tls_secret "${revision_b}" "${admission_tls_secret_b}" \
  "${rotation_barrier_service}"

jq \
  --arg barrier_label_key "${rotation_barrier_label_key}" \
  --arg barrier_label_value "${run_id}" \
  --arg wrong_digest "${bundle_digest_a}" '
    .metadata.name = "obp204-rotation-barrier"
      | .metadata.labels = {($barrier_label_key): $barrier_label_value}
      | .metadata.annotations["oxibelt.dev/supply-chain-bundle-digest"] = $wrong_digest
  ' "${work_dir}/pod-exact.json" >"${work_dir}/pod-rotation-barrier.json"
rotation_barrier_webhook="${release_name}.${namespace}.rotation-barrier.supply-chain.oxibelt.dev"
kube get validatingwebhookconfiguration "${webhook_name}" -o json \
  | jq -ce \
    --arg ca_overlap "${ca_overlap}" \
    --arg ca_b "${public_ca_b}" \
    --arg barrier_webhook "${rotation_barrier_webhook}" \
    --arg barrier_service "${rotation_barrier_service}" \
    --arg barrier_label_key "${rotation_barrier_label_key}" \
    --arg barrier_label_value "${run_id}" '
      select((.webhooks | length) == 1 and .webhooks[0].failurePolicy == "Fail")
        | [
          {op: "test", path: "/metadata/resourceVersion", value: .metadata.resourceVersion},
          {op: "test", path: "/webhooks/0/name", value: .webhooks[0].name},
          {op: "replace", path: "/webhooks/0/clientConfig/caBundle", value: $ca_overlap},
          {op: "add", path: "/webhooks/-", value: (.webhooks[0]
            | .name = $barrier_webhook
            | .clientConfig.caBundle = $ca_b
            | .clientConfig.service.name = $barrier_service
            | .objectSelector = {matchLabels: {($barrier_label_key): $barrier_label_value}}
            | .rules = [{
                apiGroups: [""],
                apiVersions: ["v1"],
                operations: ["CREATE"],
                resources: ["pods"],
                scope: "Namespaced"
              }])}
        ]
    ' >"${work_dir}/admission-overlap-barrier-patch.json"
kube patch validatingwebhookconfiguration "${webhook_name}" --type json \
  --patch-file "${work_dir}/admission-overlap-barrier-patch.json" >/dev/null
webhook_trusts_overlap_and_barrier "${ca_overlap}" "${rotation_barrier_webhook}" \
  || die "admission webhook did not retain overlap trust and the CA B barrier"
wait_for "semantic CA B trust barrier" rotation_barrier_denied
if ! expect_admitted "${work_dir}/pod-exact.json"; then
  die "canonical admission did not adopt overlapping CA trust before TLS rotation"
fi

touch "${work_dir}/rotation-probe.running"
: >"${work_dir}/rotation-probe.failures"
(
  while [[ -f "${work_dir}/rotation-probe.running" ]]; do
    if ! kube -n "${namespace}" create --dry-run=server -f "${work_dir}/pod-exact.json" \
      >/dev/null 2>>"${work_dir}/rotation-probe.failures"; then
      printf 'probe failed\n' >>"${work_dir}/rotation-probe.failures"
    fi
    sleep 1
  done
) &
rotation_probe_pid="$!"
render_admission "${fixture_a}" "${admission_tls_secret_b}" "${ca_overlap}" \
  "${work_dir}/admission-tls-b.yaml"
select_admission_documents "${work_dir}/admission-tls-b.yaml" \
  "${work_dir}/admission-tls-b-stage.yaml" stage
kube -n "${namespace}" apply -f "${work_dir}/admission-tls-b-stage.yaml" >/dev/null
deployment_targets_tls_secret "${revision_a}" "${admission_tls_secret_b}" \
  || die "admission deployment did not target TLS Secret B"
kube -n "${namespace}" rollout status "deployment/oxibelt-admission-${revision_a}" \
  --timeout="${timeout_seconds}s"
wait_for "TLS Secret B admission endpoints" \
  service_targets_revision_and_tls_secret "${revision_a}" "${admission_tls_secret_b}"
wait_for "admission with overlapping CA trust" \
  expect_admitted "${work_dir}/pod-exact.json"
kube get validatingwebhookconfiguration "${webhook_name}" -o json \
  | jq -ce \
    --arg ca_b "${public_ca_b}" \
    --arg barrier_webhook "${rotation_barrier_webhook}" '
      select((.webhooks | length) == 2 and .webhooks[1].name == $barrier_webhook)
        | [
          {op: "test", path: "/metadata/resourceVersion", value: .metadata.resourceVersion},
          {op: "test", path: "/webhooks/1/name", value: $barrier_webhook},
          {op: "replace", path: "/webhooks/0/clientConfig/caBundle", value: $ca_b},
          {op: "remove", path: "/webhooks/1"}
        ]
    ' >"${work_dir}/admission-ca-b-remove-barrier-patch.json"
kube patch validatingwebhookconfiguration "${webhook_name}" --type json \
  --patch-file "${work_dir}/admission-ca-b-remove-barrier-patch.json" >/dev/null
webhook_trusts_exact_ca_bundle "${public_ca_b}" \
  || die "admission webhook did not retain CA B after rotation"
wait_for "rotation barrier webhook removal" \
  expect_admitted "${work_dir}/pod-rotation-barrier.json"
wait_for "admission after old CA removal" expect_admitted "${work_dir}/pod-exact.json"
kube -n "${namespace}" delete service "${rotation_barrier_service}" --wait=true >/dev/null
stop_rotation_probe
if [[ -s "${work_dir}/rotation-probe.failures" ]]; then
  echo "Overlapped TLS rotation probe failures (first 40 lines):" >&2
  sed -n '1,40p' "${work_dir}/rotation-probe.failures" >&2
  die "admission requests failed during overlapped TLS rotation"
fi

kube -n "${namespace}" rollout status "deployment/oxibelt-admission-${revision_b}" \
  --timeout="${timeout_seconds}s"
expect_admitted "${work_dir}/pod-exact.json"
jq --arg digest "${bundle_digest_b}" '
  .metadata.name = "obp204-bundle-b"
  | .metadata.annotations["oxibelt.dev/supply-chain-bundle-digest"] = $digest
' "${work_dir}/pod-exact.json" >"${work_dir}/pod-bundle-b.json"
touch "${work_dir}/bundle-switch-probe.running"
: >"${work_dir}/bundle-switch-probe.failures"
(
  while [[ -f "${work_dir}/bundle-switch-probe.running" ]]; do
    if ! kube -n "${namespace}" create --dry-run=server -f "${work_dir}/pod-exact.json" \
      >/dev/null 2>&1 \
      && ! kube -n "${namespace}" create --dry-run=server -f "${work_dir}/pod-bundle-b.json" \
        >/dev/null 2>&1; then
      printf 'neither authorized bundle reached an admission endpoint\n' \
        >>"${work_dir}/bundle-switch-probe.failures"
    fi
    sleep 1
  done
) &
bundle_switch_probe_pid="$!"
kube -n "${namespace}" apply -f "${work_dir}/admission-bundle-b-switch.yaml" >/dev/null
wait_for "bundle B admission endpoints" \
  service_targets_revision_and_tls_secret "${revision_b}" "${admission_tls_secret_b}"
rm -f -- "${work_dir}/bundle-switch-probe.running"
wait "${bundle_switch_probe_pid}" >/dev/null 2>&1 || true
bundle_switch_probe_pid=""
[[ ! -s "${work_dir}/bundle-switch-probe.failures" ]] \
  || die "admission became unavailable while switching to staged bundle B"
expect_admitted "${work_dir}/pod-bundle-b.json"
expect_denied old-bundle-after-rotation "${work_dir}/pod-exact.json"

render_admission "${fixture_a}" "${admission_tls_secret_b}" "${public_ca_b}" \
  "${work_dir}/admission-bundle-a-rollback.yaml"
select_admission_documents "${work_dir}/admission-bundle-a-rollback.yaml" \
  "${work_dir}/admission-bundle-a-rollback-switch.yaml" switch
kube -n "${namespace}" apply -f "${work_dir}/admission-bundle-a-rollback-switch.yaml" >/dev/null
wait_for "bundle A rollback endpoints" \
  service_targets_revision_and_tls_secret "${revision_a}" "${admission_tls_secret_b}"
wait_for "still-authorized bundle A rollback" expect_admitted "${work_dir}/pod-exact.json"
expect_denied bundle-b-after-rollback "${work_dir}/pod-bundle-b.json"

if [[ -n "${receipt_output}" ]]; then
  [[ "${receipt_output}" == /* ]] || die "receipt output must be an absolute path"
  [[ ! -e "${receipt_output}" && -d "$(dirname -- "${receipt_output}")" ]] \
    || die "receipt output must be a new file in an existing directory"
  receipt_tmp="${work_dir}/receipt.json"
  jq -n \
    --arg revision "${source_revision}" \
    --arg provider "${provider}" \
    --arg kubernetes "$(kube version -o json | jq -r '.serverVersion.gitVersion')" \
    --arg helm "$(helm version --short)" \
    --arg strict "${strict_digest}" \
    --arg tools "${tools_digest}" \
    --arg source_dirty "${artifact_source_dirty}" \
    --arg build_kind "${artifact_build_kind}" \
    --arg bundle_a "${bundle_digest_a}" \
    --arg bundle_b "${bundle_digest_b}" '{
      schemaVersion: 1,
      result: "pass",
      sourceRevision: $revision,
      provider: $provider,
      kubernetesVersion: $kubernetes,
      helmVersion: $helm,
      strictImageDigest: $strict,
      toolsImageDigest: $tools,
      sourceDirty: $source_dirty,
      buildKind: $build_kind,
      promotionEligible: ($source_dirty == "clean"),
      bundleDigests: [$bundle_a, $bundle_b],
      evidenceScope: {
        fullV2Install: true,
        liveTlsWebhook: true,
        podClasses: ["regular", "init", "native-sidecar", "ephemeral"],
        failureClosedOutage: true,
        noninterceptedResources: ["configmaps", "pods/status", "unselected pods"],
        bundleRotationRollback: true,
        tlsOverlapRotation: true,
        networkPolicyEnforcement: false,
        nativeArchitectureQualification: false
      }
    }' >"${receipt_tmp}"
  python3 - "${receipt_tmp}" "${receipt_output}" <<'PY'
import os
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
        descriptor = -1
        output_stream.write(input_stream.read())
        output_stream.flush()
        os.fsync(output_stream.fileno())
finally:
    if descriptor >= 0:
        os.close(descriptor)
PY
fi

echo "Kubernetes supply-chain admission check passed (${provider})"
