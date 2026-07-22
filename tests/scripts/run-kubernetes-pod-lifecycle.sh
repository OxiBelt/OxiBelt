#!/usr/bin/env bash
# Exercise Deployment Pod distribution and lifecycle behavior using a uniquely
# named short-lived Kind cluster. The test uses Kind's normal Docker path and
# only stops a worker after proving it belongs to this invocation.
set -euo pipefail

umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

# Keep the Kubernetes version aligned with the chart's edge-secure-medium
# lifecycle contract and the CI-installed kubectl version.
kind_node_image="kindest/node:v1.31.14@sha256:6f86cf509dbb42767b6e79debc3f2c32e4ee01386f0489b3b2be24b0a55aac2b"
timeout_seconds="${OXIBELT_KUBERNETES_POD_LIFECYCLE_TIMEOUT_SECONDS:-600}"

if [[ "${OXIBELT_RUN_KUBERNETES_POD_LIFECYCLE:-}" != "1" ]]; then
  echo "Skipping Kubernetes Pod lifecycle test; set OXIBELT_RUN_KUBERNETES_POD_LIFECYCLE=1 to run it."
  exit 0
fi

run_id=""
cluster_name=""
namespace=""
work_dir=""
cluster_created=0
port_forward_pid=""
stopped_worker=""
workers=()
zone_labels=()

release_name="oxibelt-lifecycle"
workload_name="oxibelt"
selector="app.kubernetes.io/name=oxibelt,app.kubernetes.io/instance=${release_name}"
service_name="${workload_name}"
lifecycle_route_configmap="oxibelt-lifecycle-route"

die() {
  echo "Kubernetes Pod lifecycle test: $*" >&2
  exit 1
}

require_command() {
  local command="$1"
  command -v "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
}

kube() {
  kubectl --context "kind-${cluster_name}" "$@"
}

stop_port_forward() {
  if [[ -n "${port_forward_pid}" ]]; then
    kill "${port_forward_pid}" >/dev/null 2>&1 || true
    wait "${port_forward_pid}" >/dev/null 2>&1 || true
    port_forward_pid=""
  fi
}

cleanup() {
  local status="$?"
  set +e

  stop_port_forward

  if ((status != 0 && cluster_created == 1)); then
    echo "Kubernetes Pod lifecycle diagnostics for ${cluster_name}/${namespace}:" >&2
    node_eligibility_diagnostics >&2 || true
    kube -n "${namespace}" get deployments,pods,endpointslices,poddisruptionbudgets --ignore-not-found >&2 || true
    kube -n "${namespace}" get pods -o wide --ignore-not-found >&2 || true
    kube -n "${namespace}" get events --sort-by=.metadata.creationTimestamp >&2 || true
    kube -n "${namespace}" logs -l "${selector}" \
      --all-containers=true --prefix --tail=200 >&2 || true
    kube -n "${namespace}" logs -l "${selector}" \
      --all-containers=true --prefix --previous --tail=200 >&2 || true
  fi

  if ((cluster_created == 1)); then
    # The Kind cluster is named from this invocation only. Do not use broad
    # Docker/Kubernetes cleanup commands that could affect another checkout.
    kind delete cluster --name "${cluster_name}" >/dev/null 2>&1 || true
  fi

  case "${work_dir}" in
    "${repo_root}"/tests/.tmp/kubernetes-pod-lifecycle-*)
      rm -rf -- "${work_dir}"
      ;;
    "")
      ;;
    *)
      echo "refusing to remove unexpected test work directory: ${work_dir}" >&2
      ;;
  esac

  exit "${status}"
}
trap cleanup EXIT

wait_for() {
  local description="$1"
  local timeout="$2"
  shift 2
  local deadline=$((SECONDS + timeout))

  until "$@"; do
    if ((SECONDS >= deadline)); then
      die "timed out waiting for ${description}"
    fi
    sleep 1
  done
}

workers_are_eligible() {
  local index nodes worker zone
  nodes="$(kube get nodes -o json 2>/dev/null)" || return 1

  for index in "${!workers[@]}"; do
    worker="${workers[${index}]}"
    zone="${zone_labels[${index}]}"
    jq -e --arg worker "${worker}" --arg zone "${zone}" '
      .items[]
      | select(.metadata.name == $worker)
      | (any(.status.conditions[]?; .type == "Ready" and .status == "True"))
        and (.spec.unschedulable != true)
        and ([.spec.taints[]?
          | select(.effect == "NoSchedule" or .effect == "NoExecute")]
          | length == 0)
        and (.metadata.labels["topology.kubernetes.io/zone"] == $zone)
    ' >/dev/null <<<"${nodes}" || return 1
  done
}

node_eligibility_diagnostics() {
  local index nodes worker zone
  nodes="$(kube get nodes -o json 2>/dev/null)" || {
    echo "Node eligibility: unavailable"
    return 0
  }

  printf '%s\n' 'Node eligibility:'
  printf 'NAME\tEXPECTED-ZONE\tREADY\tUNSCHEDULABLE\tNO-SCHEDULE-OR-NO-EXECUTE-TAINTS\tACTUAL-ZONE\n'
  for index in "${!workers[@]}"; do
    worker="${workers[${index}]}"
    zone="${zone_labels[${index}]:-unknown}"
    jq -er --arg worker "${worker}" --arg zone "${zone}" '
      first(.items[] | select(.metadata.name == $worker)) as $node
      | [
          $worker,
          $zone,
          (any($node.status.conditions[]?;
            .type == "Ready" and .status == "True") | tostring),
          (($node.spec.unschedulable // false) | tostring),
          ([$node.spec.taints[]?
            | select(.effect == "NoSchedule" or .effect == "NoExecute")]
            | length | tostring),
          ($node.metadata.labels["topology.kubernetes.io/zone"] // "missing")
        ]
      | @tsv
    ' <<<"${nodes}" || printf '%s\t%s\t%s\n' "${worker}" "${zone}" 'unavailable'
  done
}

is_test_worker() {
  local node="$1"
  local kind_cluster

  case "${node}" in
    "${cluster_name}"-worker|"${cluster_name}"-worker[0-9]*)
      ;;
    *)
      return 1
      ;;
  esac

  kind_cluster="$(docker container inspect \
    --format '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}' \
    "${node}" 2>/dev/null)" || return 1
  [[ "${kind_cluster}" == "${cluster_name}" ]] || return 1

  kube get node "${node}" -o json \
    | jq -e '(.metadata.labels // {}) | has("node-role.kubernetes.io/control-plane") | not' \
    >/dev/null
}

ready_pods_json() {
  kube -n "${namespace}" get pods -l "${selector}" -o json
}

three_replicas_ready() {
  local deployment pods
  deployment="$(kube -n "${namespace}" get deployment "${workload_name}" -o json 2>/dev/null)" || return 1
  pods="$(ready_pods_json 2>/dev/null)" || return 1

  jq -e '
    (.status.availableReplicas // 0) == 3
      and (.status.readyReplicas // 0) == 3
      and (.status.updatedReplicas // 0) == 3
  ' >/dev/null <<<"${deployment}" \
    && jq -e '
      [.items[]
        | select(.metadata.deletionTimestamp == null)
        | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
      | length == 3
    ' >/dev/null <<<"${pods}"
}

pods_are_evenly_distributed() {
  local pods nodes
  pods="$(ready_pods_json 2>/dev/null)" || return 1
  nodes="$(kube get nodes -o json 2>/dev/null)" || return 1

  jq -e --argjson nodes "${nodes}" '
    (.items
      | map(select(.metadata.deletionTimestamp == null))
      | map(select(any(.status.conditions[]?; .type == "Ready" and .status == "True")))) as $pods
    | ($pods | length) == 3
    and ([ $pods[] | .spec.nodeName ] | unique | length) == 3
    and ([ $pods[] | .spec.nodeName ] | all(type == "string" and length > 0))
    and ([ $pods[] as $pod
      | $nodes.items[]
      | select(.metadata.name == $pod.spec.nodeName)
      | .metadata.labels["topology.kubernetes.io/zone"] // empty] as $zones
      | ($zones | length) == 3
      and ($zones | unique | length) == 2
      and (($zones | sort | group_by(.) | map(length)) as $counts
        | (($counts | max) - ($counts | min)) <= 1))
  ' >/dev/null <<<"${pods}"
}

pdb_allows_one_disruption() {
  local pdb
  pdb="$(kube -n "${namespace}" get poddisruptionbudget "${workload_name}" -o json 2>/dev/null)" || return 1
  jq -e '
    .spec.maxUnavailable == 1
      and .spec.unhealthyPodEvictionPolicy == "AlwaysAllow"
      and (.status.currentHealthy // 0) == 3
      and (.status.disruptionsAllowed // 0) == 1
  ' >/dev/null <<<"${pdb}"
}

monitor_rolling_update() {
  local deadline=$((SECONDS + timeout_seconds))

  while true; do
    local deployment available generation observed updated
    deployment="$(kube -n "${namespace}" get deployment "${workload_name}" -o json)" \
      || die "could not observe the lifecycle Deployment during its rolling update"
    available="$(jq -r '.status.availableReplicas // 0' <<<"${deployment}")"
    generation="$(jq -r '.metadata.generation // 0' <<<"${deployment}")"
    observed="$(jq -r '.status.observedGeneration // 0' <<<"${deployment}")"
    updated="$(jq -r '.status.updatedReplicas // 0' <<<"${deployment}")"
    [[ "${available}" =~ ^[0-9]+$ && "${generation}" =~ ^[0-9]+$ \
      && "${observed}" =~ ^[0-9]+$ && "${updated}" =~ ^[0-9]+$ ]] \
      || die "lifecycle Deployment reported nonnumeric rollout status"
    ((10#${available} >= 2)) \
      || die "rolling update reduced ready capacity below two Pods"
    if ((10#${observed} == 10#${generation} && 10#${updated} == 3 && 10#${available} == 3)); then
      return 0
    fi
    if ((SECONDS >= deadline)); then
      die "timed out waiting for the lifecycle Deployment rolling update"
    fi
    sleep 1
  done
}

terminating_pod_is_withdrawn() {
  local pod_name="$1"
  local pod endpoints
  pod="$(kube -n "${namespace}" get pod "${pod_name}" -o json 2>/dev/null)" || return 1
  endpoints="$(kube -n "${namespace}" get endpointslices \
    -l "kubernetes.io/service-name=${service_name}" -o json 2>/dev/null)" || return 1

  jq -e '.metadata.deletionTimestamp != null' >/dev/null <<<"${pod}" \
    && jq -e --arg pod "${pod_name}" '
      [.items[].endpoints[]?
        | select(.targetRef.kind == "Pod" and .targetRef.name == $pod)
        | select(.conditions.ready != false)]
      | length == 0
    ' >/dev/null <<<"${endpoints}"
}

surviving_pod_after_worker_stop() {
  local failed_worker="$1"
  local pods
  pods="$(ready_pods_json 2>/dev/null)" || return 1
  jq -e --arg failed_worker "${failed_worker}" '
    (.items
      | map(select(.metadata.deletionTimestamp == null))
      | map(select(.spec.nodeName != $failed_worker))
      | map(select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))))
    | length >= 2
  ' >/dev/null <<<"${pods}"
}

ready_health_endpoint() {
  local pod_name="$1"
  local port="$2"
  local url="http://127.0.0.1:${port}/ready"

  kube -n "${namespace}" port-forward --address 127.0.0.1 \
    "pod/${pod_name}" "${port}:9091" >"${work_dir}/port-forward-${pod_name}.log" 2>&1 &
  port_forward_pid="$!"
  wait_for "ready health response from surviving Pod ${pod_name}" 30 \
    curl --fail --silent --show-error --max-time 2 "${url}" >/dev/null
  stop_port_forward
}

for command in curl docker helm jq kind kubectl mktemp openssl sha256sum; do
  require_command "${command}"
done

if ! [[ "${timeout_seconds}" =~ ^[1-9][0-9]{2,3}$ ]] \
  || ((10#${timeout_seconds} < 180 || 10#${timeout_seconds} > 900)); then
  die "OXIBELT_KUBERNETES_POD_LIFECYCLE_TIMEOUT_SECONDS must be a decimal value from 180 through 900"
fi

# CI event values are untrusted input. Reduce them to a fixed-length lower-case
# hexadecimal identifier before using one in a cluster, namespace, or guarded
# temporary-directory name.
run_seed="${GITHUB_RUN_ID:-local}:${GITHUB_RUN_ATTEMPT:-1}:$$:${RANDOM}"
run_id="$(printf '%s' "${run_seed}" | sha256sum)"
run_id="${run_id%% *}"
run_id="${run_id:0:24}"
[[ "${run_id}" =~ ^[a-f0-9]{24}$ ]] || die "failed to derive a safe test run identifier"
cluster_name="oxibelt-lifecycle-${run_id}"
namespace="oxibelt-lifecycle-${run_id}"
work_dir="${repo_root}/tests/.tmp/kubernetes-pod-lifecycle-${run_id}"

[[ -n "${OXIBELT_DOCKER_IMAGE:-}" ]] \
  || die "OXIBELT_DOCKER_IMAGE must name the locally loaded OxiBelt image"
image="${OXIBELT_DOCKER_IMAGE}"
[[ "${image}" =~ ^[a-z0-9][a-z0-9._-]*(:[0-9]{1,5})?(/[a-z0-9][a-z0-9._-]*)*:[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || die "OXIBELT_DOCKER_IMAGE must be a lower-case local repository:tag without Helm metacharacters"
image_repository="${image%:*}"
image_tag="${image##*:}"
[[ -n "${image_repository}" && -n "${image_tag}" ]] \
  || die "OXIBELT_DOCKER_IMAGE must include non-empty repository and tag"

# Verify the configured Docker endpoint before Kind delegates image and cluster
# lifecycle operations to it.
docker version --format '{{.Server.Version}}' >/dev/null
docker image inspect "${image}" >/dev/null

if kind get clusters | grep -Fqx "${cluster_name}"; then
  die "refusing to reuse an existing Kind cluster named ${cluster_name}"
fi

mkdir -p "${work_dir}"
kind_config="${work_dir}/kind.yaml"
image_values="${work_dir}/image-values.yaml"
printf '%s\n' \
  'kind: Cluster' \
  'apiVersion: kind.x-k8s.io/v1alpha4' \
  'nodes:' \
  '- role: control-plane' \
  '- role: worker' \
  '- role: worker' \
  '- role: worker' >"${kind_config}"
printf '%s\n' \
  'image:' \
  "  repository: \"${image_repository}\"" \
  "  tag: \"${image_tag}\"" \
  '  pullPolicy: "IfNotPresent"' \
  'extraVolumes:' \
  '- name: lifecycle-route' \
  '  configMap:' \
  "    name: \"${lifecycle_route_configmap}\"" \
  '    defaultMode: 288' \
  'extraVolumeMounts:' \
  '- name: lifecycle-route' \
  '  mountPath: /etc/oxibelt/config/conf.d' \
  '  readOnly: true' >"${image_values}"

kind create cluster \
  --name "${cluster_name}" \
  --image "${kind_node_image}" \
  --config "${kind_config}" \
  --wait 120s
cluster_created=1
kind load docker-image --name "${cluster_name}" "${image}"

mapfile -t workers < <(kube get nodes -o json | jq -r '
  .items[]
  | select((.metadata.labels // {}) | has("node-role.kubernetes.io/control-plane") | not)
  | .metadata.name
' | sort)
[[ "${#workers[@]}" == "3" ]] || die "Kind lifecycle cluster must expose exactly three worker nodes"
for worker in "${workers[@]}"; do
  is_test_worker "${worker}" \
    || die "refusing to use an unverified Kind worker for this lifecycle test: ${worker}"
done

# Two zones across three workers make a three-replica Deployment prove both
# hostname separation and a max-skew-one zone spread.
zone_labels=(edge-a edge-a edge-b)
for index in "${!workers[@]}"; do
  kube label node "${workers[${index}]}" \
    "topology.kubernetes.io/zone=${zone_labels[${index}]}" --overwrite >/dev/null
done
wait_for "all lifecycle-test workers to become eligible" 120 workers_are_eligible

kube create namespace "${namespace}" >/dev/null
kube -n "${namespace}" create -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${lifecycle_route_configmap}
immutable: true
data:
  lifecycle-route.toml: |-
    [[routes]]
    name = "lifecycle-fixture"
    hosts = ["oxibelt-lifecycle.test"]
    path_prefix = "/lifecycle-fixture"

    [routes.actions.redirect]
    status = 308
    location_template = "/lifecycle-ready"
EOF
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=oxibelt-lifecycle.test' \
  -addext 'subjectAltName=DNS:oxibelt-lifecycle.test' \
  -keyout "${work_dir}/tls.key" \
  -out "${work_dir}/tls.crt" \
  >/dev/null 2>&1
kube -n "${namespace}" create secret tls oxibelt-tls \
  --cert "${work_dir}/tls.crt" \
  --key "${work_dir}/tls.key" \
  >/dev/null

chart_args=(
  -f "${image_values}"
  --set replicaCount=3
  --set service.type=ClusterIP
  --set podDistribution.enabled=true
  --set lifecycle.preStop.enabled=true
  --set lifecycle.preStop.drainSeconds=10
  --set lifecycle.terminationGracePeriodSeconds=45
  --set-json podDisruptionBudget.minAvailable=null
  --set podDisruptionBudget.maxUnavailable=1
  --set-string podDisruptionBudget.unhealthyPodEvictionPolicy=AlwaysAllow
)

helm upgrade --install "${release_name}" "${repo_root}/deploy/helm/oxibelt" \
  --kube-context "kind-${cluster_name}" \
  --namespace "${namespace}" \
  "${chart_args[@]}" \
  --wait \
  --timeout "${timeout_seconds}s"

wait_for "three Ready lifecycle-test Pods" "${timeout_seconds}" three_replicas_ready
wait_for "hostname and zone Pod distribution" 60 pods_are_evenly_distributed
wait_for "a single permitted voluntary disruption" 60 pdb_allows_one_disruption

deployment_json="$(kube -n "${namespace}" get deployment "${workload_name}" -o json)"
jq -e '
  .spec.replicas == 3
    and .spec.strategy.rollingUpdate.maxUnavailable == 0
    and .spec.strategy.rollingUpdate.maxSurge == 1
    and .spec.template.spec.terminationGracePeriodSeconds == 45
    and ([.spec.template.spec.topologySpreadConstraints[]?
      | select(.nodeTaintsPolicy == "Honor")] | length) == 2
    and any(.spec.template.spec.containers[]?;
      .name == "oxibelt"
        and .lifecycle.preStop.exec.command
          == ["/usr/local/bin/oxibelt", "__lifecycle-prestop", "--wait-seconds", "10"])
    and (.spec.template.spec.topologySpreadConstraints | length) == 2
' >/dev/null <<<"${deployment_json}" \
  || die "lifecycle Deployment does not render the expected rolling, distribution, and fixed pre-stop contract"

# An annotation-only chart change starts a normal rolling update. Sample the
# status throughout to prove the maxUnavailable=0 rollout never falls below
# two Ready replicas before the fresh ReplicaSet settles at three.
helm upgrade "${release_name}" "${repo_root}/deploy/helm/oxibelt" \
  --kube-context "kind-${cluster_name}" \
  --namespace "${namespace}" \
  "${chart_args[@]}" \
  --set-string "podAnnotations.oxibelt\\.dev/lifecycle-test-revision=${run_id}"
monitor_rolling_update
wait_for "rolled lifecycle-test Deployment" "${timeout_seconds}" three_replicas_ready

pod_to_drain="$(ready_pods_json | jq -r '
  .items
  | map(select(.metadata.deletionTimestamp == null))
  | sort_by(.metadata.name)
  | .[0].metadata.name // empty
')"
[[ -n "${pod_to_drain}" ]] || die "lifecycle Deployment did not provide a Pod to drain"
kube -n "${namespace}" delete pod "${pod_to_drain}" --wait=false >/dev/null
wait_for "terminating Pod endpoint withdrawal before exit" 20 \
  terminating_pod_is_withdrawn "${pod_to_drain}"
wait_for "replacement Pod after lifecycle drain" "${timeout_seconds}" three_replicas_ready
wait_for "replacement hostname and zone distribution" 60 pods_are_evenly_distributed

pods_json="$(ready_pods_json)"
worker_to_stop="$(jq -r '
  .items
  | map(select(.metadata.deletionTimestamp == null))
  | sort_by(.spec.nodeName, .metadata.name)
  | .[0].spec.nodeName // empty
' <<<"${pods_json}")"
[[ -n "${worker_to_stop}" ]] || die "could not identify a worker hosting a lifecycle-test Pod"
is_test_worker "${worker_to_stop}" \
  || die "refusing to stop an unverified worker: ${worker_to_stop}"

# This is deliberately a normal Docker stop against a single verified Kind
# worker. It never targets arbitrary host containers or uses broad cleanup.
docker stop "${worker_to_stop}" >/dev/null
stopped_worker="${worker_to_stop}"
docker container inspect --format '{{.State.Running}}' "${stopped_worker}" \
  | grep -Fqx false \
  || die "verified lifecycle-test worker did not stop"
wait_for "two surviving Ready Pods after a verified worker loss" 30 \
  surviving_pod_after_worker_stop "${stopped_worker}"

surviving_pod="$(ready_pods_json | jq -r --arg failed_worker "${stopped_worker}" '
  .items
  | map(select(.metadata.deletionTimestamp == null and .spec.nodeName != $failed_worker))
  | map(select(any(.status.conditions[]?; .type == "Ready" and .status == "True")))
  | sort_by(.metadata.name)
  | .[0].metadata.name // empty
')"
[[ -n "${surviving_pod}" ]] || die "worker loss left no verified surviving data-plane Pod"
ready_health_endpoint "${surviving_pod}" "$((26000 + RANDOM % 10000))"

echo "Kubernetes Pod distribution and lifecycle test passed"
