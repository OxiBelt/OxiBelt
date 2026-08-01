#!/usr/bin/env bash
# Exercise the strict Helm data plane with RuntimeDefault seccomp and
# manifest-derived Landlock. Local runs use an isolated Minikube profile by
# default; CI selects the Kind adapter while preserving the same assertions.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
chart_dir="${repo_root}/deploy/helm/oxibelt"
strict_values="${chart_dir}/examples/strict-dataplane-values.yaml"
temp_root="${TMPDIR:-/tmp}"
provider="${OXIBELT_KUBERNETES_PROVIDER:-minikube}"
timeout_seconds="${OXIBELT_STRICT_HARDENING_TIMEOUT_SECONDS:-420}"
kind_node_image="${OXIBELT_STRICT_HARDENING_KIND_NODE_IMAGE:-kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256}"
minikube_kubernetes_version="${OXIBELT_STRICT_HARDENING_MINIKUBE_KUBERNETES_VERSION:-v1.34.10}"

work_dir=""
run_id=""
cluster_name=""
namespace=""
release_name=""
kube_context=""
cluster_attempted=0
image_owned=0
image=""
port_forward_pid=""

usage() {
  echo "usage: $0 [--provider kind|minikube]" >&2
}

die() {
  echo "Helm strict hardening live check: $*" >&2
  exit 1
}

require_command() {
  local command="$1"
  command -v "${command}" >/dev/null 2>&1 \
    || die "required command is unavailable: ${command}"
}

kube() {
  kubectl --context "${kube_context}" "$@"
}

stop_port_forward() {
  if [[ -n "${port_forward_pid}" ]]; then
    if [[ "${port_forward_pid}" =~ ^[1-9][0-9]*$ ]]; then
      kill "${port_forward_pid}" >/dev/null 2>&1 || true
      wait "${port_forward_pid}" >/dev/null 2>&1 || true
    fi
    port_forward_pid=""
  fi
}

kind_cluster_is_owned() {
  local node owner
  local -a nodes=()

  mapfile -t nodes < <(kind get nodes --name "${cluster_name}" 2>/dev/null)
  ((${#nodes[@]} > 0)) || return 1
  for node in "${nodes[@]}"; do
    case "${node}" in
      "${cluster_name}"-control-plane|"${cluster_name}"-worker|"${cluster_name}"-worker[0-9]*)
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
  echo "Helm strict hardening diagnostics for ${provider}/${cluster_name}/${namespace}:" >&2
  kube get nodes -o wide >&2
  kube -n "${namespace}" get deployment,pods,events -o wide --ignore-not-found >&2
  kube -n "${namespace}" describe deployment oxibelt >&2
  kube -n "${namespace}" logs deployment/oxibelt --all-containers=true --tail=240 >&2
  kube -n "${namespace}" logs deployment/oxibelt --all-containers=true --previous --tail=240 >&2
}

cleanup() {
  local status="$?"
  set +e

  stop_port_forward
  if ((status != 0 && cluster_attempted == 1)) && [[ -n "${kube_context}" ]]; then
    diagnose
  fi

  if ((cluster_attempted == 1)); then
    case "${provider}" in
      kind)
        if kind get clusters 2>/dev/null | grep -Fqx "${cluster_name}"; then
          if kind_cluster_is_owned; then
            kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
          else
            echo "refusing to delete Kind cluster without exact ownership evidence: ${cluster_name}" >&2
          fi
        fi
        ;;
      minikube)
        # MINIKUBE_HOME is an invocation-private directory and the exact
        # generated profile name was prevalidated before start. Delete even a
        # partially created profile; never enumerate or delete other profiles.
        if [[ "${cluster_name}" =~ ^oxibelt-hardening-minikube-[a-f0-9]{16}$ ]]; then
          minikube delete --profile "${cluster_name}" >/dev/null 2>&1 || true
        fi
        ;;
    esac
  fi

  if ((image_owned == 1)) && [[ "${image}" == "oxibelt-ci/strict-hardening-live:${run_id}" ]]; then
    docker image rm "${image}" >/dev/null 2>&1 || true
  fi

  case "${work_dir}" in
    "${temp_root%/}"/oxibelt-helm-strict-hardening.*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected strict-hardening work directory: ${work_dir}" >&2
      ;;
  esac

  exit "${status}"
}
trap cleanup EXIT

while (($# > 0)); do
  case "$1" in
    --provider)
      (($# >= 2)) || { usage; exit 2; }
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
[[ "${timeout_seconds}" =~ ^[1-9][0-9]{1,3}$ ]] \
  || die "OXIBELT_STRICT_HARDENING_TIMEOUT_SECONDS must be an integer from 10 to 9999"
((timeout_seconds >= 10)) \
  || die "OXIBELT_STRICT_HARDENING_TIMEOUT_SECONDS must be at least 10"
case "${temp_root}" in
  /*)
    ;;
  *)
    die "TMPDIR must be an absolute directory"
    ;;
esac
[[ "${temp_root}" != "/" ]] || die "TMPDIR must not be the filesystem root"

for command in curl docker grep helm jq kubectl mktemp openssl sed sha256sum; do
  require_command "${command}"
done
require_command "${provider}"
[[ -d "${chart_dir}" && -f "${strict_values}" ]] \
  || die "strict Helm chart inputs are unavailable"

work_dir="$(mktemp -d "${temp_root%/}/oxibelt-helm-strict-hardening.XXXXXX")"
export KUBECONFIG="${work_dir}/kubeconfig"
run_id="$(printf '%s' "${provider}:${BASHPID}:${RANDOM}:$(date +%s%N)" | sha256sum)"
run_id="${run_id:0:16}"
[[ "${run_id}" =~ ^[a-f0-9]{16}$ ]] || die "could not derive a bounded run identifier"
cluster_name="oxibelt-hardening-${provider}-${run_id}"
namespace="oxibelt-hardening-${run_id}"
release_name="oxibelt-hardening-${run_id}"

image="${OXIBELT_STRICT_DOCKER_IMAGE:-}"
if [[ -z "${image}" ]]; then
  image="oxibelt-ci/strict-hardening-live:${run_id}"
  if docker image inspect "${image}" >/dev/null 2>&1; then
    die "refusing to overwrite the uniquely generated local image tag: ${image}"
  fi
  image_owned=1
  docker build \
    --file "${repo_root}/source/ops/Dockerfile.alpine" \
    --target dataplane-strict \
    --tag "${image}" \
    "${repo_root}"
fi
[[ "${image}" =~ ^[a-z0-9][a-z0-9._-]*(:[0-9]{1,5})?(/[a-z0-9][a-z0-9._-]*)*:[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || die "OXIBELT_STRICT_DOCKER_IMAGE must be a safe local repository:tag"
image_repository="${image%:*}"
image_tag="${image##*:}"
[[ -n "${image_repository}" && -n "${image_tag}" ]] \
  || die "OXIBELT_STRICT_DOCKER_IMAGE must include a repository and tag"
docker version --format '{{.Server.Version}}' >/dev/null
docker image inspect "${image}" >/dev/null

case "${provider}" in
  kind)
    [[ "${kind_node_image}" =~ ^kindest/node:v[0-9]+[.][0-9]+[.][0-9]+@sha256:[a-f0-9]{64}$ ]] \
      || die "OXIBELT_STRICT_HARDENING_KIND_NODE_IMAGE must be an immutable kindest/node reference"
    if kind get clusters | grep -Fqx "${cluster_name}"; then
      die "refusing to reuse an existing Kind cluster named ${cluster_name}"
    fi
    cluster_attempted=1
    kind create cluster \
      --name "${cluster_name}" \
      --image "${kind_node_image}" \
      --wait 120s
    kube_context="kind-${cluster_name}"
    kind_cluster_is_owned \
      || die "Kind nodes do not carry the exact generated cluster ownership label"
    kind load docker-image --name "${cluster_name}" "${image}"
    ;;
  minikube)
    minikube_root_compatibility=()
    if [[ "${EUID}" -eq 0 ]]; then
      docker info --format '{{json .SecurityOptions}}' | grep -Fq 'name=rootless' \
        || die "refusing Minikube's --force compatibility path unless Docker reports rootless mode"
      minikube_root_compatibility=(--force)
    fi
    export MINIKUBE_HOME="${work_dir}/minikube-home"
    mkdir -p "${MINIKUBE_HOME}"
    cluster_attempted=1
    minikube start \
      --profile "${cluster_name}" \
      --driver=docker \
      --container-runtime=containerd \
      --kubernetes-version="${minikube_kubernetes_version}" \
      --wait=all \
      --wait-timeout="${timeout_seconds}s" \
      "${minikube_root_compatibility[@]}"
    kube_context="${cluster_name}"
    minikube image load --profile "${cluster_name}" "${image}"
    ;;
esac

kube wait --for=condition=Ready node --all --timeout="${timeout_seconds}s"
kube create namespace "${namespace}" >/dev/null
kube label namespace "${namespace}" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted >/dev/null
namespace_json="$(kube get namespace "${namespace}" -o json)"
jq -e '
  .metadata.labels["pod-security.kubernetes.io/enforce"] == "restricted"
    and .metadata.labels["pod-security.kubernetes.io/audit"] == "restricted"
    and .metadata.labels["pod-security.kubernetes.io/warn"] == "restricted"
' >/dev/null <<<"${namespace_json}" \
  || die "strict-hardening namespace does not retain restricted Pod Security labels"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=oxibelt-hardening.test' \
  -addext 'subjectAltName=DNS:oxibelt-hardening.test' \
  -keyout "${work_dir}/tls.key" \
  -out "${work_dir}/tls.crt" \
  >/dev/null 2>&1
kube -n "${namespace}" create secret tls oxibelt-tls \
  --cert "${work_dir}/tls.crt" \
  --key "${work_dir}/tls.key" \
  >/dev/null

cat >"${work_dir}/live-values.yaml" <<EOF
image:
  role: dataplane-strict
  repository: "${image_repository}"
  tag: "${image_tag}"
  digest: ""
  pullPolicy: Never

replicaCount: 1

service:
  type: ClusterIP
  externalTrafficPolicy: ""
  ports:
    http:
      enabled: true
      port: 80
      targetPort: 8080
    https:
      enabled: true
      port: 443
      targetPort: 8443
    http3:
      enabled: false
      port: 443
      targetPort: 8443

metrics:
  enabled: false
  service:
    enabled: false

tls:
  enabled: true
  secretName: oxibelt-tls
  serverNames:
  - oxibelt-hardening.test

runtimeHardening:
  seccomp:
    expectation: required
    externalProfile:
      identity: ""
      digest: ""

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  seccompProfile:
    type: RuntimeDefault

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
    - ALL

config:
  inline: |
    [config]
    strict_unknown_fields = true
    warn_on_deprecated_fields = true

    [logging]
    level = "info"

    [runtime]
    linux_only = true
    read_only_rootfs_compatible = true
    memory_only_state = true
    unprivileged_mode = true
    worker_threads = "auto"
    main_runtime = "auto"

    [runtime.accept]
    workers = "auto"
    reuse_port = true
    backlog = 8192
    accept_error_backoff_ms = 10

    [runtime.hardening]
    close_range = "required"

    [runtime.hardening.landlock]
    mode = "manifest"
    read_paths = []
    read_write_paths = []

    [listeners]
    http_binds = ["0.0.0.0:8080"]
    https_binds = ["0.0.0.0:8443"]
    http_mode = "redirect_to_https"
    http1 = true
    http2 = true
    http3 = false

    [tls]
    cert_chain = "tls.crt"
    private_key = "tls.key"
    min_version = "tls1.3"
    max_version = "tls1.3"
    server_names = ["oxibelt-hardening.test"]
    require_sni = true
    reject_unknown_sni = true

    [tls.ocsp]
    mode = "disabled"

    [health]
    enabled = true
    bind = "0.0.0.0:9091"
    ready_path = "/ready"
    live_path = "/live"

    [metrics]
    enabled = false
    bind = "0.0.0.0:9090"
    format = "prometheus"
    detail = "basic"

    [overload]
    enabled = false

    [circuit_breakers]
    enabled = false

    [proxy]
    trusted_ca_certs = []

    [proxy.auto_upgrade]
    enabled = true
    max_http_version = "h2"

    [compression]
    enabled = false

    [waf]
    enabled = false
    mode = "enforcing"
    fail_policy = "closed"
EOF

helm upgrade --install "${release_name}" "${chart_dir}" \
  --kube-context "${kube_context}" \
  --namespace "${namespace}" \
  -f "${strict_values}" \
  -f "${work_dir}/live-values.yaml" \
  --wait \
  --timeout "${timeout_seconds}s"

kube -n "${namespace}" rollout status deployment/oxibelt --timeout="${timeout_seconds}s"
deployment_json="$(kube -n "${namespace}" get deployment oxibelt -o json)"
jq -e '
  .spec.replicas == 1
    and .spec.template.spec.automountServiceAccountToken == false
    and .spec.template.spec.securityContext.runAsNonRoot == true
    and .spec.template.spec.securityContext.runAsUser == 10001
    and .spec.template.spec.securityContext.runAsGroup == 10001
    and .spec.template.spec.securityContext.seccompProfile.type == "RuntimeDefault"
    and ((.spec.template.metadata.annotations // {})
      | has("oxibelt.dev/seccomp-profile-identity") | not)
    and ((.spec.template.metadata.annotations // {})
      | has("oxibelt.dev/seccomp-profile-digest") | not)
    and any(.spec.template.spec.containers[]?;
      .name == "oxibelt"
        and .command == ["/usr/local/bin/oxibelt-dataplane-strict"]
        and .securityContext.allowPrivilegeEscalation == false
        and .securityContext.readOnlyRootFilesystem == true
        and (.securityContext.capabilities.drop | index("ALL") != null)
        and ([.env[]?.name
          | select(. == "OXIBELT_SECCOMP_PROFILE_IDENTITY"
            or . == "OXIBELT_SECCOMP_PROFILE_DIGEST")] | length) == 0)
' >/dev/null <<<"${deployment_json}" \
  || die "live Deployment does not retain the strict RuntimeDefault security boundary"

logs="$(kube -n "${namespace}" logs deployment/oxibelt --all-containers=true)"
hardening_line="$(grep -F 'resolved runtime hardening contract' <<<"${logs}" | tail -n 1 || true)"
[[ -n "${hardening_line}" ]] \
  || die "strict Pod did not log the resolved hardening contract"
for expected in \
  '"outcome":"satisfied"' \
  '"requested_mode":"manifest"' \
  '"enforcement":"active"' \
  '"manifest_digest_withheld":true' \
  '"policy_digest_withheld":true' \
  '"verification":"satisfied"' \
  '"observed_mode":"filter"' \
  '"no_new_privs":"enabled"' \
  '"profile_identity_kernel_verified":false' \
  '"filesystem_manifest_digest_withheld":true'
do
  grep -F "${expected}" <<<"${hardening_line}" >/dev/null \
    || die "strict Pod hardening evidence is missing: ${expected}"
done
grep -Eq '"rule_count":[1-9][0-9]*' <<<"${hardening_line}" \
  || die "manifest Landlock did not report at least one installed rule"
if grep -F '"assertion_basis"' <<<"${hardening_line}" >/dev/null \
  || grep -F '"expected_profile_identity"' <<<"${hardening_line}" >/dev/null \
  || grep -F '"asserted_profile_identity"' <<<"${hardening_line}" >/dev/null; then
  die "RuntimeDefault incorrectly reported a semantic profile identity assertion"
fi
for raw_digest_field in \
  '"filesystem_manifest_digest":' \
  '"manifest_digest":' \
  '"policy_digest":'
do
  if grep -F "${raw_digest_field}" <<<"${hardening_line}" >/dev/null; then
    die "strict Pod hardening evidence exposed a redacted digest field: ${raw_digest_field}"
  fi
done

kube -n "${namespace}" port-forward deployment/oxibelt :9091 \
  --address 127.0.0.1 >"${work_dir}/port-forward.log" 2>&1 &
port_forward_pid="$!"
local_port=""
for _ in {1..30}; do
  if ! kill -0 "${port_forward_pid}" >/dev/null 2>&1; then
    cat "${work_dir}/port-forward.log" >&2 || true
    die "health port-forward exited before becoming ready"
  fi
  local_port="$(sed -nE 's/^Forwarding from 127[.]0[.]0[.]1:([0-9]+) -> 9091$/\1/p' \
    "${work_dir}/port-forward.log" | tail -n 1)"
  [[ -n "${local_port}" ]] && break
  sleep 1
done
[[ "${local_port}" =~ ^[1-9][0-9]{1,4}$ ]] \
  || die "could not determine the bounded local health port"
curl --fail --silent --show-error --max-time 10 \
  "http://127.0.0.1:${local_port}/ready" >/dev/null
curl --fail --silent --show-error --max-time 10 \
  "http://127.0.0.1:${local_port}/live" >/dev/null

echo "Helm strict hardening live check passed (${provider})"
